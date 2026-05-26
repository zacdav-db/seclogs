use super::model::{
    OktaActor, OktaAuthenticationContext, OktaClient, OktaDebugContext, OktaGeographicalContext,
    OktaIpChainEntry, OktaLogEvent, OktaOutcome, OktaRequest, OktaSecurityContext, OktaTarget,
    OktaTransaction, OktaUserAgent,
};
use crate::core::config::{
    OktaOutcomeResult, OktaSecurityContextConfig, OktaSeverity, OktaSystemLogEventConfig,
    OktaSystemLogSourceConfig, OktaTargetConfig, OktaTransactionType,
};
use crate::core::event::{Actor, Event, EventEnvelope, Geo, Outcome, Target};
use crate::core::identity::{Identity, IdentityRegistry, IdentityRegistryError};
use crate::core::traits::EventSource;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{Map, Number, Value};
use std::collections::{BTreeMap, VecDeque};
use toml::Value as TomlValue;

/// Okta System Log generator backed by a shared identity registry.
pub struct OktaSystemLogGenerator {
    events: VecDeque<Event>,
}

#[derive(Debug)]
pub enum OktaSystemLogError {
    IdentityRegistry(IdentityRegistryError),
    MissingIdentity(String),
    InvalidPublishedTime(String),
    EmptyStream,
}

impl std::fmt::Display for OktaSystemLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OktaSystemLogError::IdentityRegistry(err) => write!(f, "{err}"),
            OktaSystemLogError::MissingIdentity(actor_id) => {
                write!(
                    f,
                    "okta system log event references unknown actor_id: {actor_id}"
                )
            }
            OktaSystemLogError::InvalidPublishedTime(value) => {
                write!(f, "invalid okta system log published timestamp: {value}")
            }
            OktaSystemLogError::EmptyStream => {
                write!(
                    f,
                    "okta system log source needs baseline_events_per_actor or event entries"
                )
            }
        }
    }
}

impl std::error::Error for OktaSystemLogError {}

impl From<IdentityRegistryError> for OktaSystemLogError {
    fn from(err: IdentityRegistryError) -> Self {
        OktaSystemLogError::IdentityRegistry(err)
    }
}

impl OktaSystemLogGenerator {
    pub fn from_config(
        config: &OktaSystemLogSourceConfig,
        start_time: DateTime<Utc>,
    ) -> Result<Self, OktaSystemLogError> {
        let registry = IdentityRegistry::from_path(&config.identity_registry_path)?;
        Self::from_registry(config, registry, start_time)
    }

    pub fn from_registry(
        config: &OktaSystemLogSourceConfig,
        registry: IdentityRegistry,
        start_time: DateTime<Utc>,
    ) -> Result<Self, OktaSystemLogError> {
        let mut scheduled = Vec::new();
        append_injected_events(config, &registry, start_time, &mut scheduled)?;
        append_baseline_events(config, &registry, start_time, &mut scheduled);

        if scheduled.is_empty() {
            return Err(OktaSystemLogError::EmptyStream);
        }

        scheduled.sort_by(|left, right| {
            left.published
                .cmp(&right.published)
                .then(left.sequence.cmp(&right.sequence))
                .then(left.actor_id.cmp(&right.actor_id))
        });
        let events = scheduled.into_iter().map(|item| item.event).collect();
        Ok(Self { events })
    }
}

impl EventSource for OktaSystemLogGenerator {
    fn next_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }
}

struct ScheduledOktaEvent {
    published: DateTime<Utc>,
    sequence: usize,
    actor_id: String,
    event: Event,
}

struct BaselineTemplate {
    event_type: &'static str,
    display_message: &'static str,
    legacy_event_type: Option<&'static str>,
    outcome_result: OktaOutcomeResult,
    outcome_reason: Option<&'static str>,
    severity: OktaSeverity,
    credential_type: Option<&'static str>,
    debug_request_uri: &'static str,
}

fn append_injected_events(
    config: &OktaSystemLogSourceConfig,
    registry: &IdentityRegistry,
    start_time: DateTime<Utc>,
    scheduled: &mut Vec<ScheduledOktaEvent>,
) -> Result<(), OktaSystemLogError> {
    for (idx, entry) in config.events.iter().enumerate() {
        let identity = registry
            .get(&entry.actor_id)
            .ok_or_else(|| OktaSystemLogError::MissingIdentity(entry.actor_id.clone()))?;
        let published = published_for_entry(entry, start_time)?;
        let row = log_event_for_entry(identity, entry, published, idx);
        let event = event_from_row(config, identity, row);
        scheduled.push(ScheduledOktaEvent {
            published,
            sequence: idx,
            actor_id: identity.actor_id.clone(),
            event,
        });
    }
    Ok(())
}

fn append_baseline_events(
    config: &OktaSystemLogSourceConfig,
    registry: &IdentityRegistry,
    start_time: DateTime<Utc>,
    scheduled: &mut Vec<ScheduledOktaEvent>,
) {
    let count = config.baseline_events_per_actor.unwrap_or(0);
    if count == 0 {
        return;
    }

    let mut identities: Vec<&Identity> = registry.identities().iter().collect();
    identities.sort_by(|left, right| left.actor_id.cmp(&right.actor_id));
    let offset_base = config.events.len();

    for (actor_idx, identity) in identities.iter().enumerate() {
        for event_idx in 0..count {
            let seconds = 45 + (actor_idx as i64 * 29) + (event_idx as i64 * 300);
            let published = start_time + Duration::seconds(seconds);
            let sequence = offset_base + actor_idx * count + event_idx;
            let row = baseline_log_event_for_identity(
                config, identity, actor_idx, event_idx, published, sequence,
            );
            let event = event_from_row(config, identity, row);
            scheduled.push(ScheduledOktaEvent {
                published,
                sequence,
                actor_id: identity.actor_id.clone(),
                event,
            });
        }
    }
}

fn log_event_for_entry(
    identity: &Identity,
    entry: &OktaSystemLogEventConfig,
    published: DateTime<Utc>,
    sequence: usize,
) -> OktaLogEvent {
    let geo = explicit_geo_context(entry);
    let user_agent = OktaUserAgent {
        browser: entry
            .user_agent_browser
            .clone()
            .or_else(|| Some(default_browser().to_string())),
        os: entry
            .user_agent_os
            .clone()
            .or_else(|| Some(default_os().to_string())),
        raw_user_agent: entry.user_agent.clone().unwrap_or_else(default_user_agent),
    };
    let targets = if entry.targets.is_empty() {
        default_targets_for_event(identity, &entry.event_type, sequence)
    } else {
        entry
            .targets
            .iter()
            .map(target_from_config)
            .collect::<Vec<_>>()
    };
    let external_session_id = entry.external_session_id.clone().unwrap_or_else(|| {
        external_session_id_for(identity, sequence, entry.outcome_result, &entry.event_type)
    });

    OktaLogEvent {
        actor: OktaActor {
            alternate_id: identity.email.clone(),
            detail_entry: toml_option_to_json(entry.actor_detail_entry.as_ref()),
            display_name: identity.display_name.clone(),
            id: identity.okta_user_id.clone(),
            actor_type: okta_actor_type(identity).to_string(),
        },
        authentication_context: OktaAuthenticationContext {
            authentication_provider: entry
                .authentication_provider
                .clone()
                .or_else(|| Some("OKTA_AUTHENTICATION_PROVIDER".to_string())),
            authentication_step: 0,
            credential_provider: entry
                .credential_provider
                .clone()
                .or_else(|| Some("OKTA_CREDENTIAL_PROVIDER".to_string())),
            credential_type: entry
                .credential_type
                .clone()
                .or_else(|| Some("PASSWORD".to_string())),
            external_session_id,
            interface_name: None,
            issuer: Value::Null,
        },
        client: OktaClient {
            device: entry
                .client_device
                .clone()
                .or_else(|| Some(default_device().to_string())),
            geographical_context: geo.clone(),
            id: entry.client_id.clone(),
            ip_address: entry.source_ip_address.clone(),
            user_agent,
            zone: entry.client_zone.clone(),
        },
        debug_context: OktaDebugContext {
            debug_data: debug_data_for_entry(identity, entry),
        },
        display_message: entry.display_message.clone(),
        event_type: entry.event_type.clone(),
        legacy_event_type: entry
            .legacy_event_type
            .clone()
            .or_else(|| legacy_event_type_for(&entry.event_type).map(str::to_string)),
        outcome: OktaOutcome {
            reason: entry.outcome_reason.clone(),
            result: entry.outcome_result,
        },
        published: format_timestamp(published),
        request: OktaRequest {
            ip_chain: vec![ip_chain_entry(&entry.source_ip_address, geo)],
        },
        security_context: security_context_for_entry(entry.security_context.as_ref()),
        severity: entry
            .severity
            .unwrap_or_else(|| severity_for(entry.outcome_result)),
        target: targets,
        transaction: OktaTransaction {
            detail: toml_option_to_json(entry.transaction_detail.as_ref()),
            id: entry
                .transaction_id
                .clone()
                .unwrap_or_else(|| deterministic_token("txn", sequence, &identity.actor_id)),
            transaction_type: entry.transaction_type.unwrap_or(OktaTransactionType::Web),
        },
        uuid: deterministic_uuid(sequence, &identity.actor_id),
        version: "0".to_string(),
    }
}

fn baseline_log_event_for_identity(
    config: &OktaSystemLogSourceConfig,
    identity: &Identity,
    actor_idx: usize,
    event_idx: usize,
    published: DateTime<Utc>,
    sequence: usize,
) -> OktaLogEvent {
    let template = baseline_template(identity, event_idx);
    let source_ip = baseline_source_ip(config, identity, actor_idx, event_idx);
    let geo = baseline_geo_context(identity);
    let targets = baseline_targets_for_event(identity, template.event_type, event_idx);
    let transaction_type = if identity.service_account {
        OktaTransactionType::Job
    } else {
        OktaTransactionType::Web
    };

    OktaLogEvent {
        actor: OktaActor {
            alternate_id: identity.email.clone(),
            detail_entry: Value::Null,
            display_name: identity.display_name.clone(),
            id: identity.okta_user_id.clone(),
            actor_type: okta_actor_type(identity).to_string(),
        },
        authentication_context: OktaAuthenticationContext {
            authentication_provider: Some("OKTA_AUTHENTICATION_PROVIDER".to_string()),
            authentication_step: 0,
            credential_provider: Some("OKTA_CREDENTIAL_PROVIDER".to_string()),
            credential_type: template.credential_type.map(str::to_string),
            external_session_id: external_session_id_for(
                identity,
                sequence,
                template.outcome_result,
                template.event_type,
            ),
            interface_name: None,
            issuer: Value::Null,
        },
        client: OktaClient {
            device: Some(default_device().to_string()),
            geographical_context: geo.clone(),
            id: client_id_for_baseline(identity, template.event_type, sequence),
            ip_address: source_ip.clone(),
            user_agent: OktaUserAgent {
                browser: Some(default_browser().to_string()),
                os: Some(default_os().to_string()),
                raw_user_agent: default_user_agent(),
            },
            zone: Some(zone_for_identity(identity)),
        },
        debug_context: OktaDebugContext {
            debug_data: baseline_debug_data(identity, template.debug_request_uri),
        },
        display_message: template.display_message.to_string(),
        event_type: template.event_type.to_string(),
        legacy_event_type: template.legacy_event_type.map(str::to_string),
        outcome: OktaOutcome {
            reason: template.outcome_reason.map(str::to_string),
            result: template.outcome_result,
        },
        published: format_timestamp(published),
        request: OktaRequest {
            ip_chain: vec![ip_chain_entry(&source_ip, geo)],
        },
        security_context: baseline_security_context(),
        severity: template.severity,
        target: targets,
        transaction: OktaTransaction {
            detail: transaction_detail_for_baseline(template.event_type),
            id: deterministic_token("txn", sequence, &identity.actor_id),
            transaction_type,
        },
        uuid: deterministic_uuid(sequence, &identity.actor_id),
        version: "0".to_string(),
    }
}

fn event_from_row(
    config: &OktaSystemLogSourceConfig,
    identity: &Identity,
    row: OktaLogEvent,
) -> Event {
    let actor_kind = if identity.service_account {
        "service"
    } else {
        "human"
    };
    let target = row
        .target
        .iter()
        .find(|target| target.target_type == "AppInstance")
        .or_else(|| row.target.first())
        .map(|target| Target {
            id: target.id.clone(),
            kind: target.target_type.clone(),
            name: target.display_name.clone(),
        });
    let geo = geo_from_context(&row.client.geographical_context);
    let outcome = outcome_to_envelope(row.outcome.result);

    Event {
        envelope: EventEnvelope {
            schema_version: "v1".to_string(),
            timestamp: row.published.clone(),
            source: "okta_system_log".to_string(),
            event_type: row.event_type.clone(),
            actor: Actor {
                id: identity.actor_id.clone(),
                kind: actor_kind.to_string(),
                name: Some(identity.display_name.clone()),
            },
            target,
            outcome,
            geo,
            ip: Some(row.client.ip_address.clone()),
            user_agent: Some(row.client.user_agent.raw_user_agent.clone()),
            session_id: Some(row.authentication_context.external_session_id.clone()),
            tenant_id: config.org_id.clone(),
        },
        payload: row.to_value(),
    }
}

fn published_for_entry(
    entry: &OktaSystemLogEventConfig,
    start_time: DateTime<Utc>,
) -> Result<DateTime<Utc>, OktaSystemLogError> {
    if let Some(raw) = &entry.published {
        let parsed = DateTime::parse_from_rfc3339(raw)
            .map_err(|_| OktaSystemLogError::InvalidPublishedTime(raw.clone()))?;
        return Ok(parsed.with_timezone(&Utc));
    }
    Ok(start_time + Duration::seconds(entry.offset_seconds.unwrap_or(0)))
}

fn baseline_template(identity: &Identity, event_idx: usize) -> BaselineTemplate {
    if identity.service_account {
        match event_idx % 3 {
            0 => BaselineTemplate {
                event_type: "app.oauth2.token.grant.access_token",
                display_message: "OAuth 2.0 access token is granted",
                legacy_event_type: Some("app.oauth2.token.grant.access_token_success"),
                outcome_result: OktaOutcomeResult::Success,
                outcome_reason: None,
                severity: OktaSeverity::Info,
                credential_type: Some("JWT"),
                debug_request_uri: "/oauth2/v1/token",
            },
            1 => BaselineTemplate {
                event_type: "app.oauth2.authorize.code",
                display_message: "OIDC authorization request",
                legacy_event_type: Some("app.oauth2.authorize.code_success"),
                outcome_result: OktaOutcomeResult::Success,
                outcome_reason: None,
                severity: OktaSeverity::Info,
                credential_type: Some("OAuth 2.0"),
                debug_request_uri: "/oauth2/v1/authorize",
            },
            _ => BaselineTemplate {
                event_type: "app.oauth2.token.grant.id_token",
                display_message: "OAuth 2.0 ID token is granted",
                legacy_event_type: Some("app.oauth2.token.grant.id_token_success"),
                outcome_result: OktaOutcomeResult::Success,
                outcome_reason: None,
                severity: OktaSeverity::Info,
                credential_type: Some("OAuth 2.0"),
                debug_request_uri: "/oauth2/v1/token",
            },
        }
    } else {
        match event_idx % 5 {
            0 => BaselineTemplate {
                event_type: "user.session.start",
                display_message: "User login to Okta",
                legacy_event_type: Some("core.user_auth.login_success"),
                outcome_result: OktaOutcomeResult::Success,
                outcome_reason: None,
                severity: OktaSeverity::Info,
                credential_type: Some("PASSWORD"),
                debug_request_uri: "/api/v1/authn",
            },
            1 => BaselineTemplate {
                event_type: "policy.evaluate_sign_on",
                display_message: "Evaluation of sign-on policy",
                legacy_event_type: None,
                outcome_result: OktaOutcomeResult::Allow,
                outcome_reason: Some("Sign-on policy evaluation resulted in AUTHENTICATED"),
                severity: OktaSeverity::Info,
                credential_type: Some("PASSWORD"),
                debug_request_uri: "/app/common/sso/saml",
            },
            2 => BaselineTemplate {
                event_type: "user.authentication.auth_via_mfa",
                display_message: "Authentication of user via MFA",
                legacy_event_type: Some("core.user.factor.attempt_success"),
                outcome_result: OktaOutcomeResult::Success,
                outcome_reason: None,
                severity: OktaSeverity::Info,
                credential_type: Some("OTP"),
                debug_request_uri: "/api/v1/authn/factors/verify",
            },
            3 => BaselineTemplate {
                event_type: "user.authentication.sso",
                display_message: "User single sign on to app",
                legacy_event_type: Some("app.auth.sso"),
                outcome_result: OktaOutcomeResult::Success,
                outcome_reason: None,
                severity: OktaSeverity::Info,
                credential_type: Some("PASSWORD"),
                debug_request_uri: "/app/common/sso/saml",
            },
            _ => BaselineTemplate {
                event_type: "user.session.end",
                display_message: "User logout from Okta",
                legacy_event_type: Some("user.session.end"),
                outcome_result: OktaOutcomeResult::Success,
                outcome_reason: None,
                severity: OktaSeverity::Info,
                credential_type: Some("OKTA_CLIENT_SESSION"),
                debug_request_uri: "/login/signout",
            },
        }
    }
}

fn baseline_targets_for_event(
    identity: &Identity,
    event_type: &str,
    event_idx: usize,
) -> Vec<OktaTarget> {
    if event_type == "user.authentication.sso" {
        let app = app_instance_target(identity, event_idx);
        let app_user = OktaTarget {
            alternate_id: Some(identity.email.clone()),
            change_details: Value::Null,
            detail_entry: Value::Null,
            display_name: Some(identity.display_name.clone()),
            id: format!("0ua{}", stable_suffix(&identity.actor_id)),
            target_type: "AppUser".to_string(),
        };
        if event_idx % 2 == 0 {
            vec![app, app_user]
        } else {
            vec![app_user, app]
        }
    } else if event_type.starts_with("app.oauth2.") {
        vec![
            app_instance_target(identity, event_idx),
            OktaTarget {
                alternate_id: Some("default".to_string()),
                change_details: Value::Null,
                detail_entry: Value::Null,
                display_name: Some("Default Authorization Server".to_string()),
                id: format!("aus{}", stable_suffix(&identity.actor_id)),
                target_type: "AuthorizationServer".to_string(),
            },
        ]
    } else if event_type == "policy.evaluate_sign_on" {
        vec![
            policy_app_target(identity, event_idx),
            policy_rule_target(
                "rul-authentication",
                "Authentication policy",
                "Catch-all Rule",
                Some("AUTHENTICATED"),
            ),
            policy_rule_target(
                "0pr-enrollment",
                "Authenticator Enrollment Policy",
                "Default Rule",
                None,
            ),
        ]
    } else {
        Vec::new()
    }
}

fn default_targets_for_event(
    identity: &Identity,
    event_type: &str,
    sequence: usize,
) -> Vec<OktaTarget> {
    baseline_targets_for_event(identity, event_type, sequence)
}

fn app_instance_target(identity: &Identity, event_idx: usize) -> OktaTarget {
    let names = [
        "Operations Portal",
        "Analytics Workspace",
        "Service Console",
    ];
    let display_name = names[event_idx % names.len()];
    OktaTarget {
        alternate_id: Some(display_name.to_string()),
        change_details: Value::Null,
        detail_entry: object_value([
            ("signOnModeType", Value::String("OIDC".to_string())),
            ("appOwner", Value::String(identity.department.clone())),
        ]),
        display_name: Some(display_name.to_string()),
        id: format!("0oa{}", stable_suffix(display_name)),
        target_type: "AppInstance".to_string(),
    }
}

fn policy_app_target(identity: &Identity, event_idx: usize) -> OktaTarget {
    let mut target = app_instance_target(identity, event_idx);
    target.detail_entry = object_value([
        (
            "signOnModeEvaluationResult",
            Value::String("AUTHENTICATED".to_string()),
        ),
        ("signOnModeType", Value::String("SAML_2_0".to_string())),
    ]);
    target
}

fn policy_rule_target(
    id_seed: &str,
    alternate_id: &str,
    display_name: &str,
    sign_on_result: Option<&str>,
) -> OktaTarget {
    let detail_entry = match sign_on_result {
        Some(result) => object_value([(
            "signOnModeEvaluationResult",
            Value::String(result.to_string()),
        )]),
        None => Value::Null,
    };
    OktaTarget {
        alternate_id: Some(alternate_id.to_string()),
        change_details: Value::Null,
        detail_entry,
        display_name: Some(display_name.to_string()),
        id: format!("{}{}", id_seed, stable_suffix(alternate_id)),
        target_type: "Rule".to_string(),
    }
}

fn target_from_config(entry: &OktaTargetConfig) -> OktaTarget {
    OktaTarget {
        alternate_id: entry.alternate_id.clone(),
        change_details: toml_option_to_json(entry.change_details.as_ref()),
        detail_entry: toml_option_to_json(entry.detail_entry.as_ref()),
        display_name: entry.display_name.clone(),
        id: entry.id.clone(),
        target_type: entry.target_type.clone(),
    }
}

fn explicit_geo_context(entry: &OktaSystemLogEventConfig) -> OktaGeographicalContext {
    OktaGeographicalContext {
        city: entry.source_geo_city.clone(),
        country: entry.source_geo_country.clone(),
        geolocation: geolocation_value(entry.source_geo_lat, entry.source_geo_lon),
        postal_code: entry.source_geo_postal_code.clone(),
        state: entry.source_geo_region.clone(),
    }
}

fn baseline_geo_context(identity: &Identity) -> OktaGeographicalContext {
    let region = identity
        .normal_countries_regions
        .first()
        .map(String::as_str)
        .unwrap_or("Unknown");
    let (country, state, city, postal_code, lat, lon) = if region.contains("Singapore") {
        (
            Some("Singapore".to_string()),
            None,
            Some("Singapore".to_string()),
            Some("018956".to_string()),
            Some(1.3521),
            Some(103.8198),
        )
    } else if region.contains("Australia") {
        (
            Some("Australia".to_string()),
            Some("New South Wales".to_string()),
            Some("Sydney".to_string()),
            Some("2000".to_string()),
            Some(-33.8688),
            Some(151.2093),
        )
    } else {
        (Some(region.to_string()), None, None, None, None, None)
    };
    OktaGeographicalContext {
        city,
        country,
        geolocation: geolocation_value(lat, lon),
        postal_code,
        state,
    }
}

fn ip_chain_entry(ip: &str, geo: OktaGeographicalContext) -> OktaIpChainEntry {
    OktaIpChainEntry {
        geographical_context: geo,
        ip: ip.to_string(),
        ip_details: ip_details_value(),
        source: Some("client".to_string()),
        version: if ip.contains(':') { "V6" } else { "V4" }.to_string(),
    }
}

fn security_context_for_entry(entry: Option<&OktaSecurityContextConfig>) -> OktaSecurityContext {
    let Some(entry) = entry else {
        return baseline_security_context();
    };
    OktaSecurityContext {
        as_number: entry.as_number,
        as_org: entry.as_org.clone(),
        bot_protection: toml_option_to_json(entry.bot_protection.as_ref()),
        domain: entry.domain.clone(),
        ip_details: entry
            .ip_details
            .as_ref()
            .map(toml_value_to_json)
            .unwrap_or_else(ip_details_value),
        isp: entry.isp.clone(),
        is_proxy: entry.is_proxy,
        risk: toml_option_to_json(entry.risk.as_ref()),
        user_behaviors: entry
            .user_behaviors
            .as_ref()
            .map(toml_value_to_json)
            .unwrap_or_else(|| Value::Array(Vec::new())),
    }
}

fn baseline_security_context() -> OktaSecurityContext {
    OktaSecurityContext {
        as_number: Some(64500),
        as_org: Some("Corporate Network".to_string()),
        bot_protection: Value::Null,
        domain: Some("corp.internal".to_string()),
        ip_details: ip_details_value(),
        isp: Some("Corporate Network".to_string()),
        is_proxy: Some(false),
        risk: Value::Null,
        user_behaviors: Value::Array(Vec::new()),
    }
}

fn ip_details_value() -> Value {
    object_value([
        ("asNumber", Value::Number(Number::from(64500))),
        ("asOrg", Value::String("Corporate Network".to_string())),
        ("domain", Value::String("corp.internal".to_string())),
        ("isp", Value::String("Corporate Network".to_string())),
    ])
}

fn debug_data_for_entry(identity: &Identity, entry: &OktaSystemLogEventConfig) -> Value {
    if let Some(debug_data) = &entry.debug_data {
        return toml_map_to_json(debug_data);
    }
    object_value([
        (
            "requestUri",
            Value::String(default_request_uri_for(&entry.event_type).to_string()),
        ),
        (
            "requestId",
            Value::String(deterministic_token("req", 0, &identity.actor_id)),
        ),
    ])
}

fn baseline_debug_data(identity: &Identity, request_uri: &str) -> Value {
    object_value([
        ("requestUri", Value::String(request_uri.to_string())),
        (
            "requestId",
            Value::String(deterministic_token(
                "req",
                request_uri.len(),
                &identity.actor_id,
            )),
        ),
    ])
}

fn transaction_detail_for_baseline(event_type: &str) -> Value {
    if event_type.starts_with("app.oauth2.") {
        object_value([
            ("grantType", Value::String("client_credentials".to_string())),
            ("scope", Value::String("openid profile email".to_string())),
        ])
    } else if event_type == "user.authentication.sso" {
        object_value([("initiationType", Value::String("IDP_INITIATED".to_string()))])
    } else {
        Value::Null
    }
}

fn baseline_source_ip(
    config: &OktaSystemLogSourceConfig,
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
    let second = 24 + ((actor_idx / 240) % 16);
    let fourth = 20 + (actor_idx % 200);
    format!("10.{}.1.{}", second, fourth)
}

fn client_id_for_baseline(
    identity: &Identity,
    event_type: &str,
    sequence: usize,
) -> Option<String> {
    if event_type.starts_with("app.oauth2.") {
        Some(format!(
            "0oa{}",
            stable_suffix(&format!("{}-{sequence}", identity.actor_id))
        ))
    } else {
        None
    }
}

fn external_session_id_for(
    identity: &Identity,
    sequence: usize,
    result: OktaOutcomeResult,
    event_type: &str,
) -> String {
    if result == OktaOutcomeResult::Failure && event_type == "user.session.start" {
        "unknown".to_string()
    } else {
        deterministic_token("sid", sequence, &identity.actor_id)
    }
}

fn legacy_event_type_for(event_type: &str) -> Option<&str> {
    match event_type {
        "user.session.start" => Some("core.user_auth.login_success"),
        "user.authentication.sso" => Some("app.auth.sso"),
        "user.authentication.auth_via_mfa" => Some("core.user.factor.attempt_success"),
        "app.oauth2.token.grant.access_token" => {
            Some("app.oauth2.token.grant.access_token_success")
        }
        "app.oauth2.authorize.code" => Some("app.oauth2.authorize.code_success"),
        "app.oauth2.token.grant.id_token" => Some("app.oauth2.token.grant.id_token_success"),
        "policy.evaluate_sign_on" => None,
        _ => Some(event_type),
    }
}

fn default_request_uri_for(event_type: &str) -> &str {
    match event_type {
        "user.session.start" => "/api/v1/authn",
        "user.authentication.sso" => "/app/common/sso/saml",
        "policy.evaluate_sign_on" => "/app/common/sso/saml",
        "user.authentication.auth_via_mfa" => "/api/v1/authn/factors/verify",
        "user.session.end" => "/login/signout",
        "app.generic.unauth_app_access_attempt" => "/idp/idx/identify",
        "app.oauth2.token.grant.access_token" => "/oauth2/v1/token",
        "app.oauth2.authorize.code" => "/oauth2/v1/authorize",
        "app.oauth2.token.grant.id_token" => "/oauth2/v1/token",
        _ => "/api/v1/logs",
    }
}

fn okta_actor_type(identity: &Identity) -> &str {
    if identity.service_account && identity.okta_user_id.starts_with("0oa") {
        "Client"
    } else {
        "User"
    }
}

fn zone_for_identity(identity: &Identity) -> String {
    if identity
        .normal_countries_regions
        .iter()
        .any(|region| region.contains("Singapore"))
    {
        "APAC trusted".to_string()
    } else {
        "Corporate".to_string()
    }
}

fn severity_for(result: OktaOutcomeResult) -> OktaSeverity {
    match result {
        OktaOutcomeResult::Failure
        | OktaOutcomeResult::Deny
        | OktaOutcomeResult::RateLimit
        | OktaOutcomeResult::Abandoned
        | OktaOutcomeResult::Unanswered => OktaSeverity::Warn,
        _ => OktaSeverity::Info,
    }
}

fn outcome_to_envelope(result: OktaOutcomeResult) -> Outcome {
    match result {
        OktaOutcomeResult::Success | OktaOutcomeResult::Allow => Outcome::Success,
        OktaOutcomeResult::Failure
        | OktaOutcomeResult::Deny
        | OktaOutcomeResult::RateLimit
        | OktaOutcomeResult::Abandoned
        | OktaOutcomeResult::Unanswered => Outcome::Failure,
        _ => Outcome::Unknown,
    }
}

fn geo_from_context(context: &OktaGeographicalContext) -> Option<Geo> {
    context.country.as_ref().map(|country| Geo {
        country: country.clone(),
        region: context.state.clone(),
        city: context.city.clone(),
        lat: context.geolocation.get("lat").and_then(Value::as_f64),
        lon: context.geolocation.get("lon").and_then(Value::as_f64),
    })
}

fn geolocation_value(lat: Option<f64>, lon: Option<f64>) -> Value {
    match (lat, lon) {
        (Some(lat), Some(lon)) => object_value([
            (
                "lat",
                Number::from_f64(lat)
                    .map(Value::Number)
                    .unwrap_or(Value::Null),
            ),
            (
                "lon",
                Number::from_f64(lon)
                    .map(Value::Number)
                    .unwrap_or(Value::Null),
            ),
        ]),
        _ => Value::Null,
    }
}

fn object_value<const N: usize>(entries: [(&str, Value); N]) -> Value {
    let mut object = Map::new();
    for (key, value) in entries {
        object.insert(key.to_string(), value);
    }
    Value::Object(object)
}

fn toml_option_to_json(value: Option<&TomlValue>) -> Value {
    value.map(toml_value_to_json).unwrap_or(Value::Null)
}

fn toml_map_to_json(map: &BTreeMap<String, TomlValue>) -> Value {
    let mut object = Map::new();
    for (key, value) in map {
        object.insert(key.clone(), toml_value_to_json(value));
    }
    Value::Object(object)
}

fn toml_value_to_json(value: &TomlValue) -> Value {
    match value {
        TomlValue::String(value) => Value::String(value.clone()),
        TomlValue::Integer(value) => Value::Number(Number::from(*value)),
        TomlValue::Float(value) => Number::from_f64(*value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        TomlValue::Boolean(value) => Value::Bool(*value),
        TomlValue::Datetime(value) => Value::String(value.to_string()),
        TomlValue::Array(values) => Value::Array(values.iter().map(toml_value_to_json).collect()),
        TomlValue::Table(values) => {
            let mut object = Map::new();
            for (key, value) in values {
                object.insert(key.clone(), toml_value_to_json(value));
            }
            Value::Object(object)
        }
    }
}

fn format_timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn default_user_agent() -> String {
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".to_string()
}

fn default_browser() -> &'static str {
    "CHROME"
}

fn default_os() -> &'static str {
    "Mac OS X"
}

fn default_device() -> &'static str {
    "Computer"
}

fn deterministic_token(prefix: &str, sequence: usize, actor_id: &str) -> String {
    format!("{prefix}{}{:06}", stable_suffix(actor_id), sequence)
}

fn deterministic_uuid(sequence: usize, actor_id: &str) -> String {
    let left = stable_hash(&format!("{actor_id}:{sequence}:left"));
    let right = stable_hash(&format!("{actor_id}:{sequence}:right"));
    format!(
        "{:08x}-{:04x}-4{:03x}-a{:03x}-{:012x}",
        left as u32,
        (left >> 32) as u16,
        (left >> 48) as u16 & 0x0fff,
        right as u16 & 0x0fff,
        right & 0x0000_ffff_ffff_ffff
    )
}

fn stable_suffix(value: &str) -> String {
    format!("{:08x}", stable_hash(value) as u32)
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::identity::{AwsPrincipal, IdentityRegistry};
    use crate::core::traits::EventSource;
    use serde_json::Value;

    #[test]
    fn okta_system_log_output_is_deterministic() {
        let config = test_config();
        let start_time = test_start_time();
        let events_a = collect_serialized_events(generator(&config, start_time));
        let events_b = collect_serialized_events(generator(&config, start_time));

        assert_eq!(events_a, events_b);
    }

    #[test]
    fn generated_event_actors_resolve_through_registry() {
        let registry = test_registry();
        let config = test_config();
        let events = collect_events(
            OktaSystemLogGenerator::from_registry(&config, registry.clone(), test_start_time())
                .unwrap(),
        );

        for event in events {
            assert!(registry.get(&event.envelope.actor.id).is_some());
            let okta_user_id = event
                .payload
                .pointer("/actor/id")
                .and_then(Value::as_str)
                .unwrap();
            assert!(registry.resolve_okta_user_id(okta_user_id).is_some());
        }
    }

    #[test]
    fn okta_payload_preserves_camel_case_root_shape() {
        let config = test_config();
        let event = collect_events(generator(&config, test_start_time()))
            .into_iter()
            .next()
            .unwrap();
        let object = event.payload.as_object().unwrap();
        let expected = [
            "actor",
            "authenticationContext",
            "client",
            "debugContext",
            "displayMessage",
            "eventType",
            "legacyEventType",
            "outcome",
            "published",
            "request",
            "securityContext",
            "severity",
            "target",
            "transaction",
            "uuid",
            "version",
        ];

        assert_eq!(object.len(), expected.len());
        for key in expected {
            assert!(object.contains_key(key), "missing root key {key}");
        }
        assert!(!object.contains_key("authentication_context"));
        assert!(!object.contains_key("display_message"));
        assert!(event
            .payload
            .pointer("/authenticationContext/externalSessionId")
            .is_some());
        assert!(event
            .payload
            .pointer("/debugContext/debugData")
            .unwrap()
            .is_object());
    }

    #[test]
    fn client_ip_address_mirrors_first_ip_chain_entry() {
        let config = test_config();
        let events = collect_events(generator(&config, test_start_time()));

        for event in events {
            let client_ip = event
                .payload
                .pointer("/client/ipAddress")
                .and_then(Value::as_str);
            let ip_chain_ip = event
                .payload
                .pointer("/request/ipChain/0/ip")
                .and_then(Value::as_str);
            assert_eq!(client_ip, ip_chain_ip);
        }
    }

    #[test]
    fn okta_outcome_enum_values_are_preserved() {
        let values = [
            (OktaOutcomeResult::Success, "SUCCESS"),
            (OktaOutcomeResult::Failure, "FAILURE"),
            (OktaOutcomeResult::Skipped, "SKIPPED"),
            (OktaOutcomeResult::Allow, "ALLOW"),
            (OktaOutcomeResult::Deny, "DENY"),
            (OktaOutcomeResult::Challenge, "CHALLENGE"),
            (OktaOutcomeResult::Unknown, "UNKNOWN"),
            (OktaOutcomeResult::RateLimit, "RATE_LIMIT"),
            (OktaOutcomeResult::Deferred, "DEFERRED"),
            (OktaOutcomeResult::Scheduled, "SCHEDULED"),
            (OktaOutcomeResult::Abandoned, "ABANDONED"),
            (OktaOutcomeResult::Unanswered, "UNANSWERED"),
        ];

        for (value, expected) in values {
            assert_eq!(serde_json::to_value(value).unwrap(), expected);
        }

        let event = collect_events(generator(&test_config(), test_start_time()))
            .into_iter()
            .find(|event| event.envelope.event_type == "user.authentication.sso")
            .unwrap();
        assert_eq!(
            event
                .payload
                .pointer("/outcome/result")
                .and_then(Value::as_str),
            Some("DENY")
        );
        assert_eq!(
            event
                .payload
                .pointer("/legacyEventType")
                .and_then(Value::as_str),
            Some("app.auth.sso")
        );
    }

    #[test]
    fn baseline_policy_evaluation_uses_okta_sign_on_shape() {
        let event = collect_events(generator(&test_config(), test_start_time()))
            .into_iter()
            .find(|event| event.envelope.event_type == "policy.evaluate_sign_on")
            .unwrap();
        let targets = event.payload["target"].as_array().unwrap();

        assert!(event.payload["legacyEventType"].is_null());
        assert_eq!(
            event
                .payload
                .pointer("/outcome/result")
                .and_then(Value::as_str),
            Some("ALLOW")
        );
        assert_eq!(
            event
                .payload
                .pointer("/outcome/reason")
                .and_then(Value::as_str),
            Some("Sign-on policy evaluation resulted in AUTHENTICATED")
        );
        assert!(targets.iter().any(|target| target["type"] == "AppInstance"));
        assert!(targets.iter().any(|target| target["type"] == "Rule"));
    }

    #[test]
    fn example_primary_actor_has_no_singapore_baseline_travel() {
        let registry = IdentityRegistry::from_path("examples/identity_registry.toml").unwrap();
        let config = example_registry_config();
        let events = collect_events(
            OktaSystemLogGenerator::from_registry(&config, registry, test_start_time()).unwrap(),
        );

        for event in events
            .iter()
            .filter(|event| event.envelope.actor.id == "user-001")
        {
            assert_ne!(event.envelope.ip.as_deref(), Some("203.0.113.62"));
            assert_ne!(event.envelope.ip.as_deref(), Some("203.0.113.63"));
            assert_ne!(
                event.envelope.geo.as_ref().map(|geo| geo.country.as_str()),
                Some("Singapore")
            );
            assert_ne!(
                event
                    .envelope
                    .geo
                    .as_ref()
                    .and_then(|geo| geo.city.as_deref()),
                Some("Singapore")
            );
        }
    }

    #[test]
    fn example_registry_contains_benign_singapore_identities() {
        let registry = IdentityRegistry::from_path("examples/identity_registry.toml").unwrap();
        let singapore_users = registry
            .identities()
            .iter()
            .filter(|identity| identity.actor_id != "user-001")
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
    fn target_array_uses_typed_entries_without_order_assumptions() {
        let config = test_config();
        let event = collect_events(generator(&config, test_start_time()))
            .into_iter()
            .find(|event| event.envelope.event_type == "user.authentication.sso")
            .unwrap();
        let targets = event.payload["target"].as_array().unwrap();
        let app_instance = targets
            .iter()
            .find(|target| target["type"] == "AppInstance")
            .unwrap();
        let app_user = targets
            .iter()
            .find(|target| target["type"] == "AppUser")
            .unwrap();

        assert_eq!(targets[0]["type"], "AppUser");
        assert_eq!(app_instance["id"], "0oa-explicit-app");
        assert_eq!(app_user["alternateId"], "primary@example.com");
    }

    fn generator(
        config: &OktaSystemLogSourceConfig,
        start_time: DateTime<Utc>,
    ) -> OktaSystemLogGenerator {
        OktaSystemLogGenerator::from_registry(config, test_registry(), start_time).unwrap()
    }

    fn collect_serialized_events(generator: OktaSystemLogGenerator) -> Vec<Value> {
        collect_events(generator)
            .into_iter()
            .map(|event| serde_json::to_value(event).unwrap())
            .collect()
    }

    fn collect_events(mut generator: OktaSystemLogGenerator) -> Vec<Event> {
        let mut events = Vec::new();
        while let Some(event) = generator.next_event() {
            events.push(event);
        }
        events
    }

    fn test_start_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn test_config() -> OktaSystemLogSourceConfig {
        OktaSystemLogSourceConfig {
            identity_registry_path: "unused-in-unit-test.toml".to_string(),
            org_id: Some("okta-test-org".to_string()),
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
                    ("svc-job".to_string(), vec!["10.24.1.10".to_string()]),
                ]
                .into_iter()
                .collect(),
            ),
            events: vec![explicit_sso_event()],
        }
    }

    fn example_registry_config() -> OktaSystemLogSourceConfig {
        OktaSystemLogSourceConfig {
            identity_registry_path: "examples/identity_registry.toml".to_string(),
            org_id: Some("okta-example-org".to_string()),
            baseline_events_per_actor: Some(2),
            baseline_source_ips: Some(
                [
                    ("user-001".to_string(), vec!["198.51.100.10".to_string()]),
                    ("user-002".to_string(), vec!["203.0.113.62".to_string()]),
                    ("user-003".to_string(), vec!["203.0.113.63".to_string()]),
                    ("svc-001".to_string(), vec!["10.24.1.10".to_string()]),
                ]
                .into_iter()
                .collect(),
            ),
            events: Vec::new(),
        }
    }

    fn explicit_sso_event() -> OktaSystemLogEventConfig {
        OktaSystemLogEventConfig {
            actor_id: "user-primary".to_string(),
            offset_seconds: Some(10),
            published: None,
            event_type: "user.authentication.sso".to_string(),
            display_message: "User single sign on to app".to_string(),
            legacy_event_type: None,
            outcome_result: OktaOutcomeResult::Deny,
            outcome_reason: Some("USER_NOT_ASSIGNED".to_string()),
            severity: Some(OktaSeverity::Warn),
            source_ip_address: "203.0.113.45".to_string(),
            source_geo_country: Some("Example Country".to_string()),
            source_geo_region: None,
            source_geo_city: Some("Example City".to_string()),
            source_geo_postal_code: None,
            source_geo_lat: None,
            source_geo_lon: None,
            user_agent: None,
            user_agent_browser: None,
            user_agent_os: None,
            client_device: None,
            client_id: None,
            client_zone: Some("Untrusted".to_string()),
            authentication_provider: None,
            credential_provider: None,
            credential_type: None,
            external_session_id: None,
            transaction_id: None,
            transaction_type: None,
            transaction_detail: None,
            actor_detail_entry: None,
            debug_data: Some(
                [(
                    "requestUri".to_string(),
                    TomlValue::String("/app/operations/sso/saml".to_string()),
                )]
                .into_iter()
                .collect(),
            ),
            security_context: None,
            targets: vec![
                OktaTargetConfig {
                    id: "0ua-explicit-app-user".to_string(),
                    target_type: "AppUser".to_string(),
                    alternate_id: Some("primary@example.com".to_string()),
                    change_details: None,
                    detail_entry: None,
                    display_name: Some("user-primary".to_string()),
                },
                OktaTargetConfig {
                    id: "0oa-explicit-app".to_string(),
                    target_type: "AppInstance".to_string(),
                    alternate_id: Some("Operations Portal".to_string()),
                    change_details: None,
                    detail_entry: Some(TomlValue::Table(
                        [(
                            "signOnModeType".to_string(),
                            TomlValue::String("SAML_2_0".to_string()),
                        )]
                        .into_iter()
                        .collect(),
                    )),
                    display_name: Some("Operations Portal".to_string()),
                },
            ],
        }
    }

    fn test_registry() -> IdentityRegistry {
        IdentityRegistry::new(
            "test",
            vec![
                identity(
                    "user-primary",
                    "primary@example.com",
                    "00u-primary",
                    &["Australia", "Australia/NSW"],
                    false,
                ),
                identity(
                    "user-traveler",
                    "traveler@example.com",
                    "00u-traveler",
                    &["Australia", "Singapore"],
                    false,
                ),
                identity(
                    "user-singapore",
                    "singapore@example.com",
                    "00u-singapore",
                    &["Singapore"],
                    false,
                ),
                identity(
                    "svc-job",
                    "svc-job@example.com",
                    "0oa-svc-job",
                    &["Australia"],
                    true,
                ),
            ],
        )
        .unwrap()
    }

    fn identity(
        actor_id: &str,
        email: &str,
        okta_user_id: &str,
        regions: &[&str],
        service_account: bool,
    ) -> Identity {
        Identity {
            actor_id: actor_id.to_string(),
            email: email.to_string(),
            employee_id: format!("E-{actor_id}"),
            display_name: actor_id.to_string(),
            role_persona: "Test persona".to_string(),
            department: "Test department".to_string(),
            home_location: "Test location".to_string(),
            normal_countries_regions: regions.iter().map(|value| (*value).to_string()).collect(),
            okta_user_id: okta_user_id.to_string(),
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
        }
    }
}
