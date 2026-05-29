use super::model::{
    DatabricksAuditEvent, DatabricksIdentityMetadata, DatabricksResponse, DatabricksUserIdentity,
};
use crate::core::activity::{first_identity_event_at, next_identity_event_after};
use crate::core::config::{DatabricksAuditEventConfig, DatabricksAuditSourceConfig};
use crate::core::event::{Actor, Event, EventEnvelope, Geo, Outcome};
use crate::core::identity::{Identity, IdentityRegistry, IdentityRegistryError};
use crate::core::traits::EventSource;
use chrono::{DateTime, Duration, SecondsFormat, Timelike, Utc};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, VecDeque};

/// Databricks audit generator backed by a shared identity registry.
pub struct DatabricksAuditGenerator {
    config: DatabricksAuditSourceConfig,
    injected_events: VecDeque<ScheduledDatabricksEvent>,
    identities: Vec<Identity>,
    schedule: BinaryHeap<Reverse<(DateTime<Utc>, usize)>>,
    next_event_idx: Vec<usize>,
}

#[derive(Debug)]
pub enum DatabricksAuditError {
    IdentityRegistry(IdentityRegistryError),
    MissingIdentity(String),
    InvalidEventTime(String),
    EmptyStream,
}

impl std::fmt::Display for DatabricksAuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabricksAuditError::IdentityRegistry(err) => write!(f, "{err}"),
            DatabricksAuditError::MissingIdentity(actor_id) => {
                write!(
                    f,
                    "databricks audit event references unknown actor_id: {actor_id}"
                )
            }
            DatabricksAuditError::InvalidEventTime(value) => {
                write!(f, "invalid databricks audit event_time: {value}")
            }
            DatabricksAuditError::EmptyStream => {
                write!(
                    f,
                    "databricks audit source needs identity registry actors or event entries"
                )
            }
        }
    }
}

impl std::error::Error for DatabricksAuditError {}

impl From<IdentityRegistryError> for DatabricksAuditError {
    fn from(err: IdentityRegistryError) -> Self {
        DatabricksAuditError::IdentityRegistry(err)
    }
}

impl DatabricksAuditGenerator {
    pub fn from_config(
        config: &DatabricksAuditSourceConfig,
        start_time: DateTime<Utc>,
    ) -> Result<Self, DatabricksAuditError> {
        let registry = IdentityRegistry::from_path(&config.identity_registry_path)?;
        Self::from_registry(config, registry, start_time)
    }

    pub fn from_registry(
        config: &DatabricksAuditSourceConfig,
        registry: IdentityRegistry,
        start_time: DateTime<Utc>,
    ) -> Result<Self, DatabricksAuditError> {
        let mut scheduled = Vec::new();
        append_injected_events(config, &registry, start_time, &mut scheduled)?;
        let mut identities = sorted_identities(&registry);

        if scheduled.is_empty()
            && (config.baseline_events_per_actor == Some(0) || identities.is_empty())
        {
            return Err(DatabricksAuditError::EmptyStream);
        }

        scheduled.sort_by(|left, right| {
            left.event_time
                .cmp(&right.event_time)
                .then(left.sequence.cmp(&right.sequence))
                .then(left.actor_id.cmp(&right.actor_id))
        });
        let schedule = if config.baseline_events_per_actor == Some(0) {
            BinaryHeap::new()
        } else {
            build_identity_schedule(&identities, start_time)
        };
        let next_event_idx = vec![0; identities.len()];
        Ok(Self {
            config: config.clone(),
            injected_events: scheduled.into(),
            identities: std::mem::take(&mut identities),
            schedule,
            next_event_idx,
        })
    }
}

impl EventSource for DatabricksAuditGenerator {
    fn next_event(&mut self) -> Option<Event> {
        let injected_time = self.injected_events.front().map(|event| event.event_time);
        let scheduled_time = self.schedule.peek().map(|Reverse((time, _))| *time);

        match (injected_time, scheduled_time) {
            (None, None) => None,
            (Some(_), None) => self.injected_events.pop_front().map(|item| item.event),
            (Some(injected), Some(scheduled)) if injected <= scheduled => {
                self.injected_events.pop_front().map(|item| item.event)
            }
            _ => self.next_scheduled_event(),
        }
    }
}

impl DatabricksAuditGenerator {
    fn next_scheduled_event(&mut self) -> Option<Event> {
        let Reverse((event_time, actor_idx)) = self.schedule.pop()?;
        let event_idx = self.next_event_idx[actor_idx];
        self.next_event_idx[actor_idx] += 1;

        let identity = &self.identities[actor_idx];
        let row =
            baseline_row_for_identity(&self.config, identity, actor_idx, event_idx, event_time);
        let event = event_from_row(identity, row, None);

        let next_at = next_identity_event_after(
            identity,
            event_time,
            self.next_event_idx[actor_idx],
            "databricks_audit",
        );
        self.schedule.push(Reverse((next_at, actor_idx)));
        Some(event)
    }
}

struct ScheduledDatabricksEvent {
    event_time: DateTime<Utc>,
    sequence: usize,
    actor_id: String,
    event: Event,
}

fn append_injected_events(
    config: &DatabricksAuditSourceConfig,
    registry: &IdentityRegistry,
    start_time: DateTime<Utc>,
    scheduled: &mut Vec<ScheduledDatabricksEvent>,
) -> Result<(), DatabricksAuditError> {
    for (idx, entry) in config.events.iter().enumerate() {
        let identity = registry
            .get(&entry.actor_id)
            .ok_or_else(|| DatabricksAuditError::MissingIdentity(entry.actor_id.clone()))?;
        let event_time = event_time_for_entry(entry, start_time)?;
        let row = audit_row_for_entry(config, identity, entry, event_time, idx);
        let geo = geo_for_entry(entry);
        let event = event_from_row(identity, row, geo);
        scheduled.push(ScheduledDatabricksEvent {
            event_time,
            sequence: idx,
            actor_id: identity.actor_id.clone(),
            event,
        });
    }
    Ok(())
}

fn sorted_identities(registry: &IdentityRegistry) -> Vec<Identity> {
    let mut identities: Vec<&Identity> = registry.identities().iter().collect();
    identities.sort_by(|left, right| left.actor_id.cmp(&right.actor_id));
    identities.into_iter().cloned().collect()
}

fn build_identity_schedule(
    identities: &[Identity],
    start_time: DateTime<Utc>,
) -> BinaryHeap<Reverse<(DateTime<Utc>, usize)>> {
    let mut schedule = BinaryHeap::with_capacity(identities.len());
    for (idx, identity) in identities.iter().enumerate() {
        let first_at = first_identity_event_at(identity, start_time, "databricks_audit");
        schedule.push(Reverse((first_at, idx)));
    }
    schedule
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn audit_row_for_entry(
    config: &DatabricksAuditSourceConfig,
    identity: &Identity,
    entry: &DatabricksAuditEventConfig,
    event_time: DateTime<Utc>,
    sequence: usize,
) -> DatabricksAuditEvent {
    let audit_level = entry
        .audit_level
        .clone()
        .unwrap_or_else(|| audit_level_for(&entry.service_name));
    DatabricksAuditEvent {
        account_id: config.account_id.clone(),
        workspace_id: workspace_id_for(&audit_level, &config.workspace_id),
        version: "2.0".to_string(),
        event_date: event_time.format("%Y-%m-%d").to_string(),
        event_time: format_timestamp(event_time),
        source_ip_address: entry.source_ip_address.clone(),
        user_agent: entry.user_agent.clone().unwrap_or_else(default_user_agent),
        session_id: entry
            .session_id
            .clone()
            .unwrap_or_else(|| deterministic_id("dbr-session", sequence, &identity.actor_id)),
        user_identity: DatabricksUserIdentity {
            email: identity.databricks_username.clone(),
            subject_name: Some(identity.email.clone()),
        },
        service_name: entry.service_name.clone(),
        action_name: entry.action_name.clone(),
        request_id: deterministic_id("dbr-request", sequence, &entry.actor_id),
        request_params: entry.request_params.clone().unwrap_or_default(),
        response: DatabricksResponse {
            status_code: entry.response_status_code,
            error_message: entry.response_error_message.clone(),
            result: entry.response_result.clone(),
        },
        audit_level,
        event_id: deterministic_id("dbr-event", sequence, &entry.actor_id),
        identity_metadata: Some(DatabricksIdentityMetadata {
            run_by: Some(identity.email.clone()),
            run_as: Some(identity.databricks_username.clone()),
            acting_resource: None,
            run_by_display_name: Some(identity.display_name.clone()),
            run_as_display_name: Some(identity.display_name.clone()),
        }),
    }
}

fn baseline_row_for_identity(
    config: &DatabricksAuditSourceConfig,
    identity: &Identity,
    actor_idx: usize,
    event_idx: usize,
    event_time: DateTime<Utc>,
) -> DatabricksAuditEvent {
    let (service_name, action_name, mut request_params) = baseline_action(identity, event_idx);
    request_params.insert("actor_id".to_string(), identity.actor_id.clone());
    request_params.insert("baseline".to_string(), "true".to_string());

    let sequence = actor_idx * 1000 + event_idx;
    let audit_level = audit_level_for(&service_name);
    DatabricksAuditEvent {
        account_id: config.account_id.clone(),
        workspace_id: workspace_id_for(&audit_level, &config.workspace_id),
        version: "2.0".to_string(),
        event_date: event_time.format("%Y-%m-%d").to_string(),
        event_time: format_timestamp(event_time),
        source_ip_address: baseline_source_ip(config, identity, actor_idx, event_idx),
        user_agent: default_user_agent(),
        session_id: deterministic_id("dbr-session", sequence, &identity.actor_id),
        user_identity: DatabricksUserIdentity {
            email: identity.databricks_username.clone(),
            subject_name: Some(identity.email.clone()),
        },
        service_name: service_name.clone(),
        action_name,
        request_id: deterministic_id("dbr-request", sequence, &identity.actor_id),
        request_params,
        response: DatabricksResponse {
            status_code: 200,
            error_message: None,
            result: Some("SUCCESS".to_string()),
        },
        audit_level,
        event_id: deterministic_id("dbr-event", sequence, &identity.actor_id),
        identity_metadata: Some(DatabricksIdentityMetadata {
            run_by: Some(identity.email.clone()),
            run_as: Some(identity.databricks_username.clone()),
            acting_resource: None,
            run_by_display_name: Some(identity.display_name.clone()),
            run_as_display_name: Some(identity.display_name.clone()),
        }),
    }
}

fn event_from_row(identity: &Identity, row: DatabricksAuditEvent, geo: Option<Geo>) -> Event {
    let outcome = if (200..=299).contains(&row.response.status_code) {
        Outcome::Success
    } else {
        Outcome::Failure
    };
    let actor_kind = if identity.service_account {
        "service"
    } else {
        "human"
    };

    Event {
        envelope: EventEnvelope {
            schema_version: "v1".to_string(),
            timestamp: row.event_time.clone(),
            source: "databricks_audit".to_string(),
            event_type: row.action_name.clone(),
            actor: Actor {
                id: identity.actor_id.clone(),
                kind: actor_kind.to_string(),
                name: Some(identity.display_name.clone()),
            },
            target: None,
            outcome,
            geo,
            ip: Some(row.source_ip_address.clone()),
            user_agent: Some(row.user_agent.clone()),
            session_id: Some(row.session_id.clone()),
            tenant_id: Some(row.account_id.clone()),
        },
        payload: row.to_value(),
    }
}

fn event_time_for_entry(
    entry: &DatabricksAuditEventConfig,
    start_time: DateTime<Utc>,
) -> Result<DateTime<Utc>, DatabricksAuditError> {
    if let Some(raw) = &entry.event_time {
        let parsed = DateTime::parse_from_rfc3339(raw)
            .map_err(|_| DatabricksAuditError::InvalidEventTime(raw.clone()))?;
        return Ok(parsed.with_timezone(&Utc));
    }
    Ok(start_time + Duration::seconds(entry.offset_seconds.unwrap_or(0)))
}

fn geo_for_entry(entry: &DatabricksAuditEventConfig) -> Option<Geo> {
    entry.source_geo_country.as_ref().map(|country| Geo {
        country: country.clone(),
        region: entry.source_geo_region.clone(),
        city: entry.source_geo_city.clone(),
        lat: None,
        lon: None,
    })
}

fn baseline_action(
    identity: &Identity,
    event_idx: usize,
) -> (String, String, BTreeMap<String, String>) {
    let mut params = BTreeMap::new();
    if identity.service_account {
        match event_idx % 3 {
            0 => {
                params.insert(
                    "job_id".to_string(),
                    format!("job-{}", stable_suffix(&identity.actor_id)),
                );
                ("jobs".to_string(), "runNow".to_string(), params)
            }
            1 => {
                params.insert(
                    "cluster_id".to_string(),
                    format!("cluster-{}", stable_suffix(&identity.actor_id)),
                );
                ("clusters".to_string(), "get".to_string(), params)
            }
            _ => {
                params.insert("warehouse_id".to_string(), "baseline-warehouse".to_string());
                ("sql".to_string(), "commandSubmit".to_string(), params)
            }
        }
    } else {
        match event_idx % 4 {
            0 => ("accounts".to_string(), "tokenLogin".to_string(), params),
            1 => {
                params.insert("warehouse_id".to_string(), "baseline-warehouse".to_string());
                ("sql".to_string(), "commandSubmit".to_string(), params)
            }
            2 => {
                params.insert(
                    "full_name_arg".to_string(),
                    "main.default.customer_360".to_string(),
                );
                ("unityCatalog".to_string(), "getTable".to_string(), params)
            }
            _ => {
                params.insert("dashboard_id".to_string(), "baseline-dashboard".to_string());
                ("dashboards".to_string(), "getDashboard".to_string(), params)
            }
        }
    }
}

fn baseline_source_ip(
    config: &DatabricksAuditSourceConfig,
    identity: &Identity,
    actor_idx: usize,
    event_idx: usize,
) -> String {
    if let Some(source_ips) = config
        .baseline_source_ips
        .as_ref()
        .and_then(|by_actor| by_actor.get(&identity.actor_id))
    {
        if !source_ips.is_empty() {
            return source_ips[event_idx % source_ips.len()].clone();
        }
    }
    let second = 16 + ((actor_idx / 240) % 16);
    let fourth = 10 + (actor_idx % 240);
    format!("10.{}.0.{}", second, fourth)
}

fn workspace_id_for(audit_level: &str, workspace_id: &str) -> String {
    if audit_level == "ACCOUNT_LEVEL" {
        "0".to_string()
    } else {
        workspace_id.to_string()
    }
}

fn audit_level_for(service_name: &str) -> String {
    if service_name == "unityCatalog" {
        "ACCOUNT_LEVEL".to_string()
    } else {
        "WORKSPACE_LEVEL".to_string()
    }
}

fn format_timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn default_user_agent() -> String {
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".to_string()
}

fn deterministic_id(prefix: &str, sequence: usize, actor_id: &str) -> String {
    format!("{prefix}-{:06}-{}", sequence, stable_suffix(actor_id))
}

fn stable_suffix(value: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:08x}", hash as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::identity::{AwsPrincipal, IdentityRegistry};
    use crate::core::traits::EventSource;
    use serde_json::Value;

    #[test]
    fn databricks_audit_output_is_deterministic() {
        let config = test_config();
        let start_time = test_start_time();
        let events_a = collect_serialized_events(generator(&config, start_time));
        let events_b = collect_serialized_events(generator(&config, start_time));

        assert_eq!(events_a, events_b);
    }

    #[test]
    fn generated_event_identities_resolve_through_registry() {
        let registry = test_registry();
        let config = test_config();
        let events = collect_events(
            DatabricksAuditGenerator::from_registry(&config, registry.clone(), test_start_time())
                .unwrap(),
        );

        for event in events {
            assert!(registry.get(&event.envelope.actor.id).is_some());
            let email = event
                .payload
                .pointer("/user_identity/email")
                .and_then(Value::as_str)
                .unwrap();
            assert!(registry.resolve_databricks_username(email).is_some());
        }
    }

    #[test]
    fn baseline_rows_do_not_add_unconfigured_travel_to_primary_actor() {
        let config = test_config();
        let events = collect_events(generator(&config, test_start_time()));

        for event in events.iter().filter(|event| {
            event.envelope.actor.id == "user-primary"
                && event
                    .payload
                    .pointer("/request_params/baseline")
                    .and_then(Value::as_str)
                    == Some("true")
        }) {
            assert_ne!(event.envelope.ip.as_deref(), Some("203.0.113.45"));
            assert_ne!(
                event.envelope.geo.as_ref().map(|geo| geo.country.as_str()),
                Some("Singapore")
            );
        }
    }

    #[test]
    fn registry_can_contain_benign_singapore_lookalikes() {
        let registry = test_registry();
        let singapore_users = registry
            .identities()
            .iter()
            .filter(|identity| identity.actor_id != "user-primary")
            .filter(|identity| {
                identity
                    .normal_countries_regions
                    .iter()
                    .any(|region| region == "Singapore")
            })
            .count();

        assert!(singapore_users >= 2);
    }

    #[test]
    fn databricks_audit_rows_preserve_system_access_audit_shape() {
        let config = test_config();
        let event = collect_events(generator(&config, test_start_time()))
            .into_iter()
            .find(|event| event.envelope.event_type == "IpAccessDenied")
            .unwrap();

        assert_eq!(event.payload["event_time"], "2026-01-01T00:00:10.000Z");
        assert_eq!(event.payload["source_ip_address"], "203.0.113.45");
        assert_eq!(
            event
                .payload
                .pointer("/user_identity/email")
                .and_then(Value::as_str),
            Some("primary@example.com")
        );
        assert_eq!(event.payload["service_name"], "accounts");
        assert_eq!(event.payload["action_name"], "IpAccessDenied");
        assert_eq!(
            event
                .payload
                .pointer("/response/status_code")
                .and_then(Value::as_i64),
            Some(403)
        );
        assert_eq!(
            event
                .payload
                .pointer("/response/error_message")
                .and_then(Value::as_str),
            Some("Current IP is not allowed")
        );
        assert!(event.payload["request_params"].is_object());
        assert_eq!(event.payload["audit_level"], "WORKSPACE_LEVEL");
        assert_eq!(event.payload["workspace_id"], "1234567890");
        assert!(event.payload.pointer("/response/result").unwrap().is_null());
        assert!(event
            .payload
            .pointer("/identity_metadata/acting_resource")
            .unwrap()
            .is_null());
        assert_eq!(
            event
                .payload
                .pointer("/identity_metadata/run_by_display_name")
                .and_then(Value::as_str),
            Some("user-primary")
        );
    }

    #[test]
    fn scheduled_rows_follow_local_active_windows() {
        let mut config = test_config();
        config.events.clear();
        config.baseline_events_per_actor = None;
        let mut singapore = identity(
            "user-singapore",
            "singapore@example.com",
            &["Singapore"],
            false,
        );
        singapore.rate_per_hour = Some(6.0);
        singapore.active_start_hour = Some(8);
        singapore.active_hours = Some(10);
        singapore.timezone_offset = Some(8);
        singapore.weekend_active = Some(false);
        let mut london = identity(
            "user-london",
            "london@example.com",
            &["United Kingdom"],
            false,
        );
        london.rate_per_hour = Some(6.0);
        london.active_start_hour = Some(8);
        london.active_hours = Some(10);
        london.timezone_offset = Some(0);
        london.weekend_active = Some(false);
        let registry = IdentityRegistry::new("test", vec![singapore, london]).unwrap();
        let start = DateTime::parse_from_rfc3339("2026-01-05T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut generator =
            DatabricksAuditGenerator::from_registry(&config, registry, start).unwrap();

        let mut singapore_workday = 0;
        let mut singapore_off_hours = 0;
        let mut london_workday = 0;
        let mut london_off_hours = 0;
        for _ in 0..900 {
            let event = generator.next_event().unwrap();
            let hour = DateTime::parse_from_rfc3339(&event.envelope.timestamp)
                .unwrap()
                .with_timezone(&Utc)
                .hour();
            match event.envelope.actor.id.as_str() {
                "user-singapore" if (0..10).contains(&hour) => singapore_workday += 1,
                "user-singapore" if !(0..10).contains(&hour) => singapore_off_hours += 1,
                "user-london" if (8..18).contains(&hour) => london_workday += 1,
                "user-london" if !(8..18).contains(&hour) => london_off_hours += 1,
                _ => {}
            }
        }

        assert!(
            singapore_workday > singapore_off_hours * 2,
            "singapore_workday={singapore_workday} singapore_off_hours={singapore_off_hours}"
        );
        assert!(
            london_workday > london_off_hours * 2,
            "london_workday={london_workday} london_off_hours={london_off_hours}"
        );
    }

    fn generator(
        config: &DatabricksAuditSourceConfig,
        start_time: DateTime<Utc>,
    ) -> DatabricksAuditGenerator {
        DatabricksAuditGenerator::from_registry(config, test_registry(), start_time).unwrap()
    }

    fn collect_serialized_events(generator: DatabricksAuditGenerator) -> Vec<Value> {
        collect_events(generator)
            .into_iter()
            .map(|event| serde_json::to_value(event).unwrap())
            .collect()
    }

    fn collect_events(mut generator: DatabricksAuditGenerator) -> Vec<Event> {
        let mut events = Vec::new();
        for _ in 0..32 {
            if let Some(event) = generator.next_event() {
                events.push(event);
            }
        }
        events
    }

    fn test_start_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn test_config() -> DatabricksAuditSourceConfig {
        DatabricksAuditSourceConfig {
            identity_registry_path: "unused-in-unit-test.toml".to_string(),
            account_id: "acc-123".to_string(),
            workspace_id: "1234567890".to_string(),
            baseline_events_per_actor: Some(2),
            baseline_source_ips: Some(
                [
                    (
                        "user-primary".to_string(),
                        vec!["198.51.100.10".to_string()],
                    ),
                    (
                        "user-traveler".to_string(),
                        vec!["203.0.113.61".to_string()],
                    ),
                    (
                        "user-singapore".to_string(),
                        vec!["203.0.113.62".to_string()],
                    ),
                ]
                .into_iter()
                .collect(),
            ),
            events: vec![DatabricksAuditEventConfig {
                actor_id: "user-primary".to_string(),
                offset_seconds: Some(10),
                event_time: None,
                source_ip_address: "203.0.113.45".to_string(),
                service_name: "accounts".to_string(),
                action_name: "IpAccessDenied".to_string(),
                request_params: Some(
                    [("login_type".to_string(), "browser".to_string())]
                        .into_iter()
                        .collect(),
                ),
                response_status_code: 403,
                response_error_message: Some("Current IP is not allowed".to_string()),
                response_result: None,
                user_agent: None,
                session_id: None,
                audit_level: None,
                source_geo_country: Some("Singapore".to_string()),
                source_geo_region: None,
                source_geo_city: Some("Singapore".to_string()),
            }],
        }
    }

    fn test_registry() -> IdentityRegistry {
        IdentityRegistry::new(
            "test",
            vec![
                identity(
                    "user-primary",
                    "primary@example.com",
                    &["Australia", "Australia/NSW"],
                    false,
                ),
                identity(
                    "user-traveler",
                    "traveler@example.com",
                    &["Australia", "Singapore"],
                    false,
                ),
                identity(
                    "user-singapore",
                    "singapore@example.com",
                    &["Singapore"],
                    false,
                ),
                identity("svc-job", "svc-job@example.com", &["Australia"], true),
            ],
        )
        .unwrap()
    }

    fn identity(actor_id: &str, email: &str, regions: &[&str], service_account: bool) -> Identity {
        Identity {
            actor_id: actor_id.to_string(),
            email: email.to_string(),
            employee_id: format!("E-{actor_id}"),
            display_name: actor_id.to_string(),
            role_persona: "Test persona".to_string(),
            department: "Test department".to_string(),
            home_location: "Test location".to_string(),
            normal_countries_regions: regions.iter().map(|value| (*value).to_string()).collect(),
            okta_user_id: format!("okta-{actor_id}"),
            databricks_username: email.to_string(),
            aws_principals: vec![AwsPrincipal {
                account_id: "123456789012".to_string(),
                principal_id: format!("AIDA{actor_id}"),
                arn: format!("arn:aws:iam::123456789012:user/{actor_id}"),
                role_name: None,
                role_session_name: None,
                access_key_id: Some(format!("AKIA{actor_id}")),
            }],
            service_account,
            tags: Vec::new(),
            rate_per_hour: None,
            active_start_hour: None,
            active_hours: None,
            timezone_offset: None,
            weekend_active: None,
            service_pattern: None,
        }
    }
}
