use crate::catalog::{resolve_event_weights, CatalogError, EventSelector, WeightedEvent};
use crate::templates::{
    build_cloudtrail_event, default_error_profile, ActorContext, ErrorProfile,
};
use chrono::{SecondsFormat, Utc};
use rand::distributions::{Distribution, WeightedIndex};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use seclog_core::config::{CloudTrailSourceConfig, EventErrorConfig, RoleWeight};
use seclog_core::event::{Actor, Event, EventEnvelope, Outcome};
use seclog_core::traits::EventSource;
use std::collections::{HashMap, HashSet};

pub struct CloudTrailGenerator {
    selector: EventSelector,
    rng: StdRng,
    actors: Vec<ActorProfile>,
    event_weights: HashMap<String, f64>,
    allowed_events: HashSet<String>,
    error_profiles: HashMap<String, ErrorProfile>,
}

impl CloudTrailGenerator {
    pub fn from_config(
        config: &CloudTrailSourceConfig,
        seed: Option<u64>,
    ) -> Result<Self, CatalogError> {
        let events = resolve_event_weights(config)?;
        let selector = EventSelector::new(events.clone())?;
        Ok(Self::new(selector, events, config, seed))
    }

    pub fn new(
        selector: EventSelector,
        events: Vec<WeightedEvent>,
        config: &CloudTrailSourceConfig,
        seed: Option<u64>,
    ) -> Self {
        let rng = match seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        };
        let mut event_weights = HashMap::new();
        let mut allowed_events = HashSet::new();
        for event in events {
            event_weights.insert(event.name.clone(), event.weight);
            allowed_events.insert(event.name);
        }

        let actor_count = config.actor_count.unwrap_or(500).max(1);
        let service_ratio = config.service_ratio.unwrap_or(0.2).clamp(0.0, 1.0);
        let roles = build_role_weights(config.role_distribution.as_ref());
        let actors = build_actor_pool(&rng, actor_count, service_ratio, roles);
        let error_profiles = build_error_profiles(config.error_rates.as_ref());

        Self {
            selector,
            rng,
            actors,
            event_weights,
            allowed_events,
            error_profiles,
        }
    }
}

impl EventSource for CloudTrailGenerator {
    fn next_event(&mut self) -> Option<Event> {
        let actor_index = self.next_actor_index();
        let event_name = self.pick_event_for_actor(actor_index);
        let event_time = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);

        let actor_context = actor_context(&self.actors[actor_index]);
        let error_profile = self
            .error_profiles
            .get(&event_name)
            .cloned()
            .or_else(|| default_error_profile(&event_name));
        let cloudtrail =
            build_cloudtrail_event(
                &event_name,
                &actor_context,
                &mut self.rng,
                &event_time,
                error_profile,
            )
            .ok()?;

        let envelope = EventEnvelope {
            schema_version: "v1".to_string(),
            timestamp: cloudtrail.event_time.clone(),
            source: "cloudtrail".to_string(),
            event_type: cloudtrail.event_name.clone(),
            actor: Actor {
                id: cloudtrail.user_identity.principal_id.clone(),
                kind: cloudtrail.user_identity.identity_type.clone(),
                name: cloudtrail.user_identity.user_name.clone(),
            },
            target: None,
            outcome: if cloudtrail.error_code.is_some() {
                Outcome::Failure
            } else {
                Outcome::Success
            },
            geo: None,
            ip: Some(cloudtrail.source_ip_address.clone()),
            user_agent: Some(cloudtrail.user_agent.clone()),
            session_id: None,
            tenant_id: Some(cloudtrail.recipient_account_id.clone()),
        };

        Some(Event {
            envelope,
            payload: cloudtrail.to_value(),
        })
    }
}

fn build_actor_pool(
    rng: &StdRng,
    total: usize,
    service_ratio: f64,
    role_weights: Vec<(ActorRole, f64)>,
) -> Vec<ActorProfile> {
    let mut rng = rng.clone();
    let service_count = ((total as f64) * service_ratio).round() as usize;
    let human_count = total.saturating_sub(service_count);
    let mut actors = Vec::with_capacity(total);

    for _ in 0..human_count {
        actors.push(ActorProfile::new_human(&mut rng, &role_weights));
    }
    for _ in 0..service_count {
        actors.push(ActorProfile::new_service(&mut rng));
    }

    actors
}

impl CloudTrailGenerator {
    fn next_actor_index(&mut self) -> usize {
        self.rng.gen_range(0..self.actors.len())
    }

    fn pick_event_for_actor(&mut self, actor_index: usize) -> String {
        let (kind, last_event) = {
            let actor = &mut self.actors[actor_index];
            actor.maybe_reset_session(&mut self.rng);
            (actor.kind.clone(), actor.last_event.clone())
        };

        let candidates = match kind {
            ActorKind::Human(role) => human_candidates(role, last_event.as_deref()),
            ActorKind::Service => service_candidates(last_event.as_deref()),
        };

        let event = self.pick_weighted_event(&candidates);
        let actor = &mut self.actors[actor_index];
        actor.last_event = Some(event.clone());
        actor.consume_session(&mut self.rng);
        event
    }

    fn pick_weighted_event(&mut self, candidates: &[(String, f64)]) -> String {
        let mut names = Vec::new();
        let mut weights = Vec::new();

        for (name, weight) in candidates {
            if !self.allowed_events.contains(name) {
                continue;
            }
            let base = *self.event_weights.get(name).unwrap_or(&1.0);
            names.push(name.clone());
            weights.push(base * *weight);
        }

        if names.is_empty() {
            return self.selector.choose(&mut self.rng).name.clone();
        }

        let index = WeightedIndex::new(&weights).ok();
        if let Some(index) = index {
            let idx = index.sample(&mut self.rng);
            return names[idx].clone();
        }

        self.selector.choose(&mut self.rng).name.clone()
    }
}

fn human_candidates(role: ActorRole, last: Option<&str>) -> Vec<(String, f64)> {
    match role {
        ActorRole::Admin => admin_candidates(last),
        ActorRole::Developer => developer_candidates(last),
        ActorRole::ReadOnly => readonly_candidates(last),
        ActorRole::Auditor => auditor_candidates(last),
    }
}

fn service_candidates(last: Option<&str>) -> Vec<(String, f64)> {
    match last {
        None => vec![
            ("AssumeRole".to_string(), 2.0),
            ("GetCallerIdentity".to_string(), 1.0),
            ("PutLogEvents".to_string(), 1.2),
        ],
        Some("AssumeRole") | Some("GetCallerIdentity") => vec![
            ("PutObject".to_string(), 1.2),
            ("GetObject".to_string(), 1.2),
            ("PutLogEvents".to_string(), 1.6),
            ("DescribeInstances".to_string(), 0.6),
            ("RunInstances".to_string(), 0.2),
        ],
        _ => vec![
            ("PutLogEvents".to_string(), 1.8),
            ("GetObject".to_string(), 1.1),
            ("PutObject".to_string(), 0.9),
            ("DescribeInstances".to_string(), 0.6),
        ],
    }
}

#[derive(Debug, Clone)]
enum ActorKind {
    Human(ActorRole),
    Service,
}

#[derive(Debug, Clone)]
enum ActorRole {
    Admin,
    Developer,
    ReadOnly,
    Auditor,
}

#[derive(Debug, Clone)]
struct ActorProfile {
    kind: ActorKind,
    identity_type: String,
    principal_id: String,
    arn: String,
    account_id: String,
    user_name: Option<String>,
    user_agent: String,
    source_ip: String,
    last_event: Option<String>,
    session_remaining: u8,
}

impl ActorProfile {
    fn new_human(rng: &mut impl Rng, role_weights: &[(ActorRole, f64)]) -> Self {
        let account_id = random_account_id(rng);
        let user_name = format!("user-{}", random_alpha(rng, 6).to_lowercase());
        let principal_id = format!("AIDA{}", random_alpha(rng, 16));
        let arn = format!("arn:aws:iam::{}:user/{}", account_id, user_name);
        let user_agent = random_human_user_agent(rng);
        let role = pick_human_role(rng, role_weights);
        Self {
            kind: ActorKind::Human(role),
            identity_type: "IAMUser".to_string(),
            principal_id,
            arn,
            account_id,
            user_name: Some(user_name),
            user_agent,
            source_ip: random_ip(rng),
            last_event: None,
            session_remaining: 0,
        }
    }

    fn new_service(rng: &mut impl Rng) -> Self {
        let account_id = random_account_id(rng);
        let role_name = format!("svc-role-{}", random_alpha(rng, 4).to_lowercase());
        let session_name = format!("svc-{}", random_alpha(rng, 8));
        let principal_id = format!("AROA{}", random_alpha(rng, 16));
        let arn = format!(
            "arn:aws:sts::{}:assumed-role/{}/{}",
            account_id, role_name, session_name
        );
        let user_agent = random_service_user_agent(rng);
        Self {
            kind: ActorKind::Service,
            identity_type: "AssumedRole".to_string(),
            principal_id,
            arn,
            account_id,
            user_name: None,
            user_agent,
            source_ip: random_private_ip(rng),
            last_event: None,
            session_remaining: 0,
        }
    }

    fn maybe_reset_session(&mut self, rng: &mut impl Rng) {
        if self.session_remaining == 0 {
            self.last_event = None;
            self.session_remaining = match self.kind {
                ActorKind::Human(_) => rng.gen_range(3..10),
                ActorKind::Service => rng.gen_range(6..18),
            };
        }
    }

    fn consume_session(&mut self, rng: &mut impl Rng) {
        if self.session_remaining > 0 {
            self.session_remaining -= 1;
        }
        if self.session_remaining == 0 && rng.gen_bool(0.2) {
            self.last_event = None;
        }
    }
}

fn actor_context(actor: &ActorProfile) -> ActorContext {
    ActorContext {
        identity_type: actor.identity_type.clone(),
        principal_id: actor.principal_id.clone(),
        arn: actor.arn.clone(),
        account_id: actor.account_id.clone(),
        user_name: actor.user_name.clone(),
        user_agent: actor.user_agent.clone(),
        source_ip: actor.source_ip.clone(),
    }
}

fn admin_candidates(last: Option<&str>) -> Vec<(String, f64)> {
    match last {
        None => vec![
            ("ConsoleLogin".to_string(), 3.0),
            ("GetSessionToken".to_string(), 1.0),
            ("AssumeRole".to_string(), 1.5),
            ("GetCallerIdentity".to_string(), 0.6),
        ],
        Some("ConsoleLogin") => vec![
            ("GetSessionToken".to_string(), 1.4),
            ("AssumeRole".to_string(), 2.5),
            ("CreateUser".to_string(), 0.6),
            ("CreateAccessKey".to_string(), 0.5),
            ("AttachRolePolicy".to_string(), 0.4),
        ],
        Some("AssumeRole") => vec![
            ("CreateUser".to_string(), 0.6),
            ("AttachRolePolicy".to_string(), 0.5),
            ("UpdateAccessKey".to_string(), 0.4),
            ("DescribeInstances".to_string(), 0.7),
        ],
        _ => vec![
            ("DescribeInstances".to_string(), 0.8),
            ("GetCallerIdentity".to_string(), 0.6),
            ("CreateSecurityGroup".to_string(), 0.3),
            ("AuthorizeSecurityGroupIngress".to_string(), 0.3),
        ],
    }
}

fn developer_candidates(last: Option<&str>) -> Vec<(String, f64)> {
    match last {
        None => vec![
            ("ConsoleLogin".to_string(), 2.6),
            ("GetSessionToken".to_string(), 0.9),
            ("AssumeRole".to_string(), 1.8),
            ("GetCallerIdentity".to_string(), 0.5),
        ],
        Some("ConsoleLogin") => vec![
            ("GetSessionToken".to_string(), 1.2),
            ("AssumeRole".to_string(), 2.4),
            ("RunInstances".to_string(), 0.8),
            ("CreateSecurityGroup".to_string(), 0.6),
            ("PutObject".to_string(), 0.6),
        ],
        Some("AssumeRole") => vec![
            ("RunInstances".to_string(), 0.9),
            ("DescribeInstances".to_string(), 1.0),
            ("PutObject".to_string(), 1.0),
            ("GetObject".to_string(), 0.8),
        ],
        _ => vec![
            ("DescribeInstances".to_string(), 1.0),
            ("PutObject".to_string(), 0.9),
            ("GetObject".to_string(), 0.8),
            ("CreateLogGroup".to_string(), 0.4),
        ],
    }
}

fn readonly_candidates(last: Option<&str>) -> Vec<(String, f64)> {
    match last {
        None => vec![
            ("ConsoleLogin".to_string(), 2.8),
            ("GetSessionToken".to_string(), 0.7),
            ("AssumeRole".to_string(), 1.2),
            ("GetCallerIdentity".to_string(), 0.6),
        ],
        Some("ConsoleLogin") => vec![
            ("GetSessionToken".to_string(), 0.8),
            ("DescribeInstances".to_string(), 1.2),
            ("GetObject".to_string(), 1.0),
            ("GetCallerIdentity".to_string(), 0.6),
        ],
        Some("AssumeRole") => vec![
            ("DescribeInstances".to_string(), 1.2),
            ("GetObject".to_string(), 1.1),
            ("GetCallerIdentity".to_string(), 0.6),
        ],
        _ => vec![
            ("DescribeInstances".to_string(), 1.2),
            ("GetObject".to_string(), 1.0),
            ("GetCallerIdentity".to_string(), 0.5),
        ],
    }
}

fn auditor_candidates(last: Option<&str>) -> Vec<(String, f64)> {
    match last {
        None => vec![
            ("ConsoleLogin".to_string(), 2.2),
            ("GetSessionToken".to_string(), 0.8),
            ("AssumeRole".to_string(), 1.4),
            ("GetCallerIdentity".to_string(), 0.8),
        ],
        Some("ConsoleLogin") => vec![
            ("GetSessionToken".to_string(), 0.9),
            ("GetCallerIdentity".to_string(), 0.9),
            ("DescribeInstances".to_string(), 0.9),
            ("PutLogEvents".to_string(), 1.2),
            ("CreateLogGroup".to_string(), 0.4),
        ],
        Some("AssumeRole") => vec![
            ("PutLogEvents".to_string(), 1.5),
            ("DescribeInstances".to_string(), 0.8),
            ("GetObject".to_string(), 0.6),
        ],
        _ => vec![
            ("PutLogEvents".to_string(), 1.4),
            ("DescribeInstances".to_string(), 0.8),
            ("GetCallerIdentity".to_string(), 0.6),
        ],
    }
}

fn pick_human_role(rng: &mut impl Rng, role_weights: &[(ActorRole, f64)]) -> ActorRole {
    if role_weights.is_empty() {
        return ActorRole::Developer;
    }

    let weights: Vec<f64> = role_weights.iter().map(|(_, weight)| *weight).collect();
    if let Ok(dist) = WeightedIndex::new(&weights) {
        return role_weights[dist.sample(rng)].0.clone();
    }

    ActorRole::Developer
}

fn random_alpha(rng: &mut impl Rng, len: usize) -> String {
    const ALPHANUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..ALPHANUM.len());
            ALPHANUM[idx] as char
        })
        .collect()
}

fn random_account_id(rng: &mut impl Rng) -> String {
    (0..12).map(|_| rng.gen_range(0..10).to_string()).collect()
}

fn random_ip(rng: &mut impl Rng) -> String {
    format!(
        "{}.{}.{}.{}",
        rng.gen_range(1..=223),
        rng.gen_range(0..=255),
        rng.gen_range(0..=255),
        rng.gen_range(1..=254)
    )
}

fn random_private_ip(rng: &mut impl Rng) -> String {
    match rng.gen_range(0..3) {
        0 => format!("10.{}.{}.{}", rng.gen_range(0..=255), rng.gen_range(0..=255), rng.gen_range(1..=254)),
        1 => format!(
            "192.168.{}.{}",
            rng.gen_range(0..=255),
            rng.gen_range(1..=254)
        ),
        _ => format!(
            "172.{}.{}.{}",
            rng.gen_range(16..=31),
            rng.gen_range(0..=255),
            rng.gen_range(1..=254)
        ),
    }
}

fn random_human_user_agent(rng: &mut impl Rng) -> String {
    match rng.gen_range(0..6) {
        0 => {
            let major = rng.gen_range(16..18);
            let safari = format!("{}.{}", rng.gen_range(605..607), rng.gen_range(1..20));
            format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_2) AppleWebKit/{} (KHTML, like Gecko) Version/{}.{} Safari/{}",
                safari,
                major,
                rng.gen_range(0..3),
                safari
            )
        }
        1 => {
            let major = rng.gen_range(118..123);
            format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36",
                major
            )
        }
        2 => {
            let major = rng.gen_range(117..121);
            format!(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36",
                major
            )
        }
        3 => {
            let major = rng.gen_range(116..121);
            format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Gecko/20100101 Firefox/{}.0",
                major
            )
        }
        4 => {
            let major = rng.gen_range(16..18);
            format!(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_{} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{}.0 Mobile/15E148 Safari/604.1",
                rng.gen_range(0..3),
                major
            )
        }
        _ => {
            let major = rng.gen_range(118..123);
            let edge_build = rng.gen_range(1700..2400);
            format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/{}.0.{}.{}",
                major,
                edge_build,
                rng.gen_range(10..90)
            )
        }
    }
}

fn random_service_user_agent(rng: &mut impl Rng) -> String {
    match rng.gen_range(0..10) {
        0 => format!("aws-cli/2.{}.{}", rng.gen_range(10..18), rng.gen_range(0..5)),
        1 => format!(
            "aws-sdk-go/1.{}.{} (go1.{})",
            rng.gen_range(40..51),
            rng.gen_range(0..10),
            rng.gen_range(18..22)
        ),
        2 => format!(
            "aws-sdk-java/1.12.{} Linux/5.15 OpenJDK_64-Bit_Server_VM",
            rng.gen_range(500..700)
        ),
        3 => format!("aws-sdk-js/2.{}.0", rng.gen_range(1450..1600)),
        4 => format!(
            "Boto3/1.{}.{} Python/3.11.{} Linux/5.15",
            rng.gen_range(28..36),
            rng.gen_range(0..10),
            rng.gen_range(0..10)
        ),
        5 => format!(
            "Terraform/1.{}.{} (+https://www.terraform.io)",
            rng.gen_range(5..8),
            rng.gen_range(0..10)
        ),
        6 => format!(
            "Pulumi/3.{}.{} (linux; x64)",
            rng.gen_range(80..110),
            rng.gen_range(0..10)
        ),
        7 => format!("DatadogAgent/7.{}.{}", rng.gen_range(40..50), rng.gen_range(0..10)),
        8 => format!("Vault/1.{}.{}", rng.gen_range(10..15), rng.gen_range(0..10)),
        _ => format!("AWSInternal/3.{}", rng.gen_range(0..5)),
    }
}

fn build_error_profiles(config: Option<&Vec<EventErrorConfig>>) -> HashMap<String, ErrorProfile> {
    let mut map = HashMap::new();
    if let Some(entries) = config {
        for entry in entries {
            if !entry.rate.is_finite() || entry.rate < 0.0 || entry.rate > 1.0 {
                continue;
            }
            let fallback = default_error_profile(&entry.name);
            let code = entry
                .code
                .clone()
                .or_else(|| fallback.as_ref().map(|profile| profile.code.clone()))
                .unwrap_or_else(|| "AccessDenied".to_string());
            let message = entry
                .message
                .clone()
                .or_else(|| fallback.as_ref().map(|profile| profile.message.clone()))
                .unwrap_or_else(|| "Access denied".to_string());
            map.insert(
                entry.name.clone(),
                ErrorProfile {
                    rate: entry.rate,
                    code,
                    message,
                },
            );
        }
    }
    map
}

fn build_role_weights(config: Option<&Vec<RoleWeight>>) -> Vec<(ActorRole, f64)> {
    let defaults = vec![
        (ActorRole::Admin, 0.15),
        (ActorRole::Developer, 0.55),
        (ActorRole::ReadOnly, 0.25),
        (ActorRole::Auditor, 0.05),
    ];

    let entries = match config {
        Some(list) if !list.is_empty() => list,
        _ => return defaults,
    };

    let mut parsed = Vec::new();
    for entry in entries {
        if !entry.weight.is_finite() || entry.weight <= 0.0 {
            continue;
        }
        let role = match entry.name.as_str() {
            "admin" => ActorRole::Admin,
            "developer" => ActorRole::Developer,
            "readonly" | "read_only" => ActorRole::ReadOnly,
            "auditor" => ActorRole::Auditor,
            _ => continue,
        };
        parsed.push((role, entry.weight));
    }

    if parsed.is_empty() {
        defaults
    } else {
        parsed
    }
}
