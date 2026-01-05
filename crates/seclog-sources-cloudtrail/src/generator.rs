use crate::catalog::{resolve_event_weights, CatalogError, EventSelector, WeightedEvent};
use crate::templates::{
    build_cloudtrail_event, default_error_profile, ActorContext, ErrorProfile,
};
use chrono::{DateTime, SecondsFormat, Utc};
use rand::distributions::{Distribution, WeightedIndex};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use seclog_core::actors::{ActorKind, ActorPopulation, ActorProfile, ActorRole};
use seclog_core::config::{CloudTrailSourceConfig, EventErrorConfig, RegionWeight, RoleWeight};
use seclog_core::event::{Actor, Event, EventEnvelope, Outcome};
use seclog_core::traits::EventSource;
use seclog_actors_parquet as actor_store;
use std::collections::{HashMap, HashSet};

/// CloudTrail event source with weighted event selection and actor sessions.
pub struct CloudTrailGenerator {
    selector: EventSelector,
    rng: StdRng,
    actors: Vec<ActorProfile>,
    actor_selector: WeightedIndex<f64>,
    event_weights: HashMap<String, f64>,
    allowed_events: HashSet<String>,
    error_profiles: HashMap<String, ErrorProfile>,
    region_selector: RegionSelector,
}

impl CloudTrailGenerator {
    /// Builds a generator from the CloudTrail config and optional seed.
    pub fn from_config(
        config: &CloudTrailSourceConfig,
        seed: Option<u64>,
    ) -> Result<Self, CatalogError> {
        let events = resolve_event_weights(config)?;
        let selector = EventSelector::new(events.clone())?;
        Self::new(selector, events, config, seed)
    }

    /// Builds a generator from a prepared selector and event list.
    pub fn new(
        selector: EventSelector,
        events: Vec<WeightedEvent>,
        config: &CloudTrailSourceConfig,
        seed: Option<u64>,
    ) -> Result<Self, CatalogError> {
        let mut rng = match seed {
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
        let region_selector =
            build_region_selector(config.regions.as_ref(), config.region_distribution.as_ref());
        let account_ids = build_account_pool(config);
        let mut actors = load_actor_profiles(
            &mut rng,
            config,
            actor_count,
            service_ratio,
            &roles,
            &account_ids,
        )?;
        shuffle_actors(&mut actors, &mut rng);
        let actor_selector = build_actor_selector(
            actors.len(),
            config.hot_actor_ratio.unwrap_or(0.1),
            config.hot_actor_share.unwrap_or(0.6),
        );
        let error_profiles = build_error_profiles(config.error_rates.as_ref());

        Ok(Self {
            selector,
            rng,
            actors,
            actor_selector,
            event_weights,
            allowed_events,
            error_profiles,
            region_selector,
        })
    }
}

impl EventSource for CloudTrailGenerator {
    fn next_event(&mut self) -> Option<Event> {
        let now = Utc::now();
        let actor_index = self.next_active_actor_index(now)?;
        let event_name = self.pick_event_for_actor(actor_index, now);
        let event_time = now.to_rfc3339_opts(SecondsFormat::Millis, true);

        let region = self.region_selector.pick(&mut self.rng);
        let actor_context = actor_context(&mut self.actors[actor_index], region, &mut self.rng);
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

fn load_actor_profiles(
    rng: &mut StdRng,
    config: &CloudTrailSourceConfig,
    total: usize,
    service_ratio: f64,
    role_weights: &[(ActorRole, f64)],
    account_ids: &[String],
) -> Result<Vec<ActorProfile>, CatalogError> {
    let population = if let Some(path) = &config.actor_population_path {
        actor_store::read_population(path)
            .map_err(|err| CatalogError::Population(err.to_string()))?
    } else {
        ActorPopulation::generate(rng, total, service_ratio, role_weights, account_ids)
    };
    Ok(population.profiles())
}

/// Generates a reusable actor population based on CloudTrail config.
pub fn generate_actor_population(
    config: &CloudTrailSourceConfig,
    seed: Option<u64>,
) -> ActorPopulation {
    let mut rng = match seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_entropy(),
    };
    let actor_count = config.actor_count.unwrap_or(500).max(1);
    let service_ratio = config.service_ratio.unwrap_or(0.2).clamp(0.0, 1.0);
    let roles = build_role_weights(config.role_distribution.as_ref());
    let account_ids = build_account_pool(config);
    ActorPopulation::generate(&mut rng, actor_count, service_ratio, &roles, &account_ids)
}

impl CloudTrailGenerator {
    fn next_actor_index(&mut self) -> usize {
        self.actor_selector.sample(&mut self.rng)
    }

    fn next_active_actor_index(&mut self, now: DateTime<Utc>) -> Option<usize> {
        let attempts = self.actors.len().min(64).max(1);
        for _ in 0..attempts {
            let idx = self.next_actor_index();
            if self.actors[idx].is_available(now, &mut self.rng) {
                return Some(idx);
            }
        }

        for idx in 0..self.actors.len() {
            if self.actors[idx].is_available(now, &mut self.rng) {
                return Some(idx);
            }
        }

        None
    }

    fn pick_event_for_actor(&mut self, actor_index: usize, now: DateTime<Utc>) -> String {
        let (kind, last_event) = {
            let actor = &mut self.actors[actor_index];
            actor.ensure_session(now, &mut self.rng);
            (actor.seed.kind.clone(), actor.last_event.clone())
        };

        let candidates = match kind {
            ActorKind::Human => {
                let role = actor_role_or_default(&self.actors[actor_index]);
                human_candidates(role, last_event.as_deref())
            }
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

fn actor_role_or_default(actor: &ActorProfile) -> ActorRole {
    actor
        .seed
        .role
        .clone()
        .unwrap_or(ActorRole::Developer)
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

fn actor_context(
    actor: &mut ActorProfile,
    region: String,
    rng: &mut impl Rng,
) -> ActorContext {
    ActorContext {
        identity_type: actor.seed.identity_type.clone(),
        principal_id: actor.seed.principal_id.clone(),
        arn: actor.seed.arn.clone(),
        account_id: actor.seed.account_id.clone(),
        user_name: actor.seed.user_name.clone(),
        user_agent: actor.current_user_agent(rng),
        source_ip: actor.current_source_ip(rng),
        region,
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

fn random_account_id(rng: &mut impl Rng) -> String {
    (0..12).map(|_| rng.gen_range(0..10).to_string()).collect()
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

fn build_actor_selector(count: usize, hot_ratio: f64, hot_share: f64) -> WeightedIndex<f64> {
    if count == 0 {
        return WeightedIndex::new(vec![1.0]).expect("non-empty weights");
    }

    let ratio = hot_ratio.clamp(0.0, 1.0);
    let share = hot_share.clamp(0.0, 1.0);
    let hot_count = ((count as f64) * ratio).round() as usize;
    let hot_count = hot_count.clamp(1, count);
    let cold_count = count.saturating_sub(hot_count);

    if cold_count == 0 || share == 0.0 || share == 1.0 {
        return WeightedIndex::new(vec![1.0; count]).expect("non-empty weights");
    }

    let hot_weight = share / hot_count as f64;
    let cold_weight = (1.0 - share) / cold_count as f64;

    let mut weights = Vec::with_capacity(count);
    for _ in 0..hot_count {
        weights.push(hot_weight);
    }
    for _ in 0..cold_count {
        weights.push(cold_weight);
    }

    WeightedIndex::new(weights).unwrap_or_else(|_| WeightedIndex::new(vec![1.0; count]).unwrap())
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

struct RegionSelector {
    regions: Vec<String>,
    weights: WeightedIndex<f64>,
}

impl RegionSelector {
    fn pick(&self, rng: &mut impl Rng) -> String {
        let idx = self.weights.sample(rng);
        self.regions[idx].clone()
    }
}

fn build_region_selector(
    regions: Option<&Vec<String>>,
    distribution: Option<&Vec<RegionWeight>>,
) -> RegionSelector {
    let defaults = vec![
        "us-east-1".to_string(),
        "us-west-2".to_string(),
        "eu-west-1".to_string(),
        "ap-southeast-1".to_string(),
    ];

    let mut base_regions = Vec::new();
    let mut seen = HashSet::new();
    if let Some(list) = regions {
        for entry in list {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            if seen.insert(trimmed.to_string()) {
                base_regions.push(trimmed.to_string());
            }
        }
    }

    if base_regions.is_empty() {
        if let Some(list) = distribution {
            for entry in list {
                if !entry.weight.is_finite() || entry.weight <= 0.0 {
                    continue;
                }
                let trimmed = entry.name.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if seen.insert(trimmed.to_string()) {
                    base_regions.push(trimmed.to_string());
                }
            }
        }
    }

    if base_regions.is_empty() {
        base_regions = defaults;
    }

    let mut weight_map = HashMap::new();
    if let Some(list) = distribution {
        for entry in list {
            if !entry.weight.is_finite() || entry.weight <= 0.0 {
                continue;
            }
            let trimmed = entry.name.trim();
            if trimmed.is_empty() {
                continue;
            }
            weight_map.insert(trimmed.to_string(), entry.weight);
        }
    }

    let weights: Vec<f64> = base_regions
        .iter()
        .map(|region| *weight_map.get(region).unwrap_or(&1.0))
        .collect();

    let index = WeightedIndex::new(weights).unwrap_or_else(|_| {
        let weights = vec![1.0; base_regions.len()];
        WeightedIndex::new(weights).expect("fallback weights")
    });

    RegionSelector {
        regions: base_regions,
        weights: index,
    }
}

fn build_account_pool(config: &CloudTrailSourceConfig) -> Vec<String> {
    if let Some(ids) = &config.account_ids {
        let filtered: Vec<String> = ids.iter().cloned().filter(|id| id.len() == 12).collect();
        if !filtered.is_empty() {
            return filtered;
        }
    }

    let count = config.account_count.unwrap_or(1).max(1);
    let mut rng = rand::thread_rng();
    (0..count).map(|_| random_account_id(&mut rng)).collect()
}

fn shuffle_actors(actors: &mut [ActorProfile], rng: &mut impl Rng) {
    for idx in (1..actors.len()).rev() {
        let swap_idx = rng.gen_range(0..=idx);
        actors.swap(idx, swap_idx);
    }
}
