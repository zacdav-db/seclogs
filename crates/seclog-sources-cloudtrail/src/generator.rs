use crate::catalog::{resolve_event_weights, CatalogError, EventSelector, WeightedEvent};
use crate::templates::{build_cloudtrail_event, default_error_profile, ActorContext};
use chrono::{DateTime, Duration, SecondsFormat, Timelike, Utc};
use rand::distributions::{Distribution, WeightedIndex};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use seclog_core::actors::{ActorKind, ActorProfile, ActorRole, ServicePattern, ServiceProfile};
use seclog_core::config::CloudTrailSourceConfig;
use seclog_core::event::{Actor, Event, EventEnvelope, Outcome};
use seclog_core::traits::EventSource;
use seclog_actors_parquet as actor_store;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

/// CloudTrail event source with weighted event selection and actor sessions.
pub struct CloudTrailGenerator {
    selector: EventSelector,
    rng: StdRng,
    actors: Vec<ActorProfile>,
    schedule: BinaryHeap<Reverse<(DateTime<Utc>, usize)>>,
    event_weights: HashMap<String, f64>,
    allowed_events: HashSet<String>,
    region_selector: RegionSelector,
}

impl CloudTrailGenerator {
    /// Builds a generator from the CloudTrail config and optional seed.
    pub fn from_config(
        config: &CloudTrailSourceConfig,
        seed: Option<u64>,
        start_time: DateTime<Utc>,
    ) -> Result<Self, CatalogError> {
        let events = resolve_event_weights(config)?;
        let selector = EventSelector::new(events.clone())?;
        Self::new(selector, events, config, seed, start_time)
    }

    /// Builds a generator from a prepared selector and event list.
    pub fn new(
        selector: EventSelector,
        events: Vec<WeightedEvent>,
        config: &CloudTrailSourceConfig,
        seed: Option<u64>,
        start_time: DateTime<Utc>,
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

        let region_selector =
            build_region_selector(config.regions.as_ref(), config.region_distribution.as_ref());
        let mut actors = load_actor_profiles(config)?;
        shuffle_actors(&mut actors, &mut rng);
        let schedule = build_schedule(&actors, start_time, &mut rng);
        Ok(Self {
            selector,
            rng,
            actors,
            schedule,
            event_weights,
            allowed_events,
            region_selector,
        })
    }
}

impl EventSource for CloudTrailGenerator {
    fn next_event(&mut self) -> Option<Event> {
        loop {
            let Reverse((now, actor_index)) = self.schedule.pop()?;
            if !self.actors[actor_index].is_available(now, &mut self.rng) {
                let next_at = self.actors[actor_index].next_available_at(now);
                self.schedule.push(Reverse((next_at, actor_index)));
                continue;
            }

            let event_name = self.pick_event_for_actor(actor_index, now);
            let event_time = now.to_rfc3339_opts(SecondsFormat::Millis, true);

            let region = self.region_selector.pick(&mut self.rng);
            let (actor_context, error_rate) = {
                let actor = &mut self.actors[actor_index];
                let error_rate = actor.seed.error_rate;
                (actor_context(actor, region, &mut self.rng), error_rate)
            };
            let error_profile = default_error_profile(&event_name);
            let cloudtrail =
                build_cloudtrail_event(
                    &event_name,
                    &actor_context,
                    &mut self.rng,
                    &event_time,
                    error_profile,
                    error_rate,
                )
                .ok()?;

            {
                let actor = &mut self.actors[actor_index];
                actor.consume_session(&mut self.rng);
                let next_at = schedule_after(actor, now, &mut self.rng);
                self.schedule.push(Reverse((next_at, actor_index)));
            }

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

            return Some(Event {
                envelope,
                payload: cloudtrail.to_value(),
            });
        }
    }
}

fn load_actor_profiles(
    config: &CloudTrailSourceConfig,
) -> Result<Vec<ActorProfile>, CatalogError> {
    let path = config.actor_population_path.as_ref().ok_or_else(|| {
        CatalogError::Population("actor_population_path is required".to_string())
    })?;
    let population = actor_store::read_population(path)
        .map_err(|err| CatalogError::Population(err.to_string()))?;
    Ok(population.profiles())
}

impl CloudTrailGenerator {
    fn pick_event_for_actor(&mut self, actor_index: usize, now: DateTime<Utc>) -> String {
        let (kind, last_event, service_profile) = {
            let actor = &mut self.actors[actor_index];
            actor.ensure_session(now, &mut self.rng);
            (
                actor.seed.kind.clone(),
                actor.last_event.clone(),
                actor.seed.service_profile.clone(),
            )
        };

        let candidates = match kind {
            ActorKind::Human => {
                let role = actor_role_or_default(&self.actors[actor_index]);
                human_candidates(role, last_event.as_deref())
            }
            ActorKind::Service => {
                service_profile_candidates(service_profile.as_ref(), last_event.as_deref())
            }
        };

        let event = self.pick_weighted_event(&candidates);
        let actor = &mut self.actors[actor_index];
        actor.last_event = Some(event.clone());
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

fn service_profile_candidates(
    profile: Option<&ServiceProfile>,
    last: Option<&str>,
) -> Vec<(String, f64)> {
    match profile.unwrap_or(&ServiceProfile::Generic) {
        ServiceProfile::Generic => service_candidates(last),
        ServiceProfile::Ec2Reaper => ec2_reaper_candidates(last),
        ServiceProfile::DataLakeBot => datalake_bot_candidates(last),
        ServiceProfile::LogsShipper => logs_shipper_candidates(last),
        ServiceProfile::MetricsCollector => metrics_collector_candidates(last),
    }
}

fn ec2_reaper_candidates(last: Option<&str>) -> Vec<(String, f64)> {
    match last {
        None => vec![
            ("AssumeRole".to_string(), 1.2),
            ("GetCallerIdentity".to_string(), 0.8),
            ("DescribeInstances".to_string(), 1.6),
        ],
        Some("AssumeRole") | Some("GetCallerIdentity") => vec![
            ("DescribeInstances".to_string(), 2.0),
            ("StopInstances".to_string(), 0.9),
            ("TerminateInstances".to_string(), 1.4),
            ("StartInstances".to_string(), 0.5),
        ],
        _ => vec![
            ("DescribeInstances".to_string(), 2.1),
            ("TerminateInstances".to_string(), 1.6),
            ("StopInstances".to_string(), 0.9),
            ("StartInstances".to_string(), 0.4),
        ],
    }
}

fn datalake_bot_candidates(last: Option<&str>) -> Vec<(String, f64)> {
    match last {
        None => vec![
            ("AssumeRole".to_string(), 1.1),
            ("GetCallerIdentity".to_string(), 0.7),
            ("CreateBucket".to_string(), 0.6),
            ("PutObject".to_string(), 1.2),
        ],
        Some("AssumeRole") | Some("GetCallerIdentity") => vec![
            ("PutObject".to_string(), 2.2),
            ("GetObject".to_string(), 1.6),
            ("DeleteObject".to_string(), 0.6),
            ("Encrypt".to_string(), 1.2),
            ("Decrypt".to_string(), 1.0),
            ("GenerateDataKey".to_string(), 0.9),
            ("PutLogEvents".to_string(), 0.8),
        ],
        _ => vec![
            ("PutObject".to_string(), 2.1),
            ("GetObject".to_string(), 1.5),
            ("DeleteObject".to_string(), 0.6),
            ("Encrypt".to_string(), 1.1),
            ("Decrypt".to_string(), 0.9),
            ("GenerateDataKey".to_string(), 0.9),
            ("PutLogEvents".to_string(), 0.7),
        ],
    }
}

fn logs_shipper_candidates(last: Option<&str>) -> Vec<(String, f64)> {
    match last {
        None => vec![
            ("AssumeRole".to_string(), 1.2),
            ("GetCallerIdentity".to_string(), 0.7),
            ("CreateLogGroup".to_string(), 0.6),
            ("CreateLogStream".to_string(), 1.0),
        ],
        Some("AssumeRole") | Some("GetCallerIdentity") => vec![
            ("CreateLogStream".to_string(), 1.3),
            ("DescribeLogStreams".to_string(), 1.1),
            ("PutLogEvents".to_string(), 2.2),
        ],
        _ => vec![
            ("PutLogEvents".to_string(), 2.4),
            ("CreateLogStream".to_string(), 1.1),
            ("DescribeLogStreams".to_string(), 1.0),
            ("CreateLogGroup".to_string(), 0.4),
        ],
    }
}

fn metrics_collector_candidates(last: Option<&str>) -> Vec<(String, f64)> {
    match last {
        None => vec![
            ("AssumeRole".to_string(), 1.0),
            ("GetCallerIdentity".to_string(), 0.8),
            ("ListMetrics".to_string(), 0.9),
            ("PutMetricData".to_string(), 1.1),
        ],
        Some("AssumeRole") | Some("GetCallerIdentity") => vec![
            ("GetMetricData".to_string(), 1.5),
            ("PutMetricData".to_string(), 1.2),
            ("ListMetrics".to_string(), 0.8),
        ],
        _ => vec![
            ("GetMetricData".to_string(), 1.6),
            ("PutMetricData".to_string(), 1.1),
            ("ListMetrics".to_string(), 0.8),
        ],
    }
}

fn actor_context(
    actor: &mut ActorProfile,
    region: String,
    rng: &mut impl Rng,
) -> ActorContext {
    let user_agent = actor.current_user_agent(rng);
    let session_credential_from_console = user_agent.contains("CloudShell")
        || user_agent.starts_with("Mozilla/")
        || user_agent.contains("Safari/")
        || user_agent.contains("Chrome/");
    let mfa_authenticated = match actor.seed.kind {
        ActorKind::Human => rng.gen_bool(0.7),
        ActorKind::Service => false,
    };
    ActorContext {
        identity_type: actor.seed.identity_type.clone(),
        principal_id: actor.seed.principal_id.clone(),
        arn: actor.seed.arn.clone(),
        account_id: actor.seed.account_id.clone(),
        access_key_id: Some(actor.seed.access_key_id.clone()),
        user_name: actor.seed.user_name.clone(),
        user_agent,
        source_ip: actor.current_source_ip(rng),
        region,
        mfa_authenticated,
        session_credential_from_console,
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

fn build_schedule(
    actors: &[ActorProfile],
    start_time: DateTime<Utc>,
    rng: &mut impl Rng,
) -> BinaryHeap<Reverse<(DateTime<Utc>, usize)>> {
    let mut heap = BinaryHeap::with_capacity(actors.len());
    for (idx, actor) in actors.iter().enumerate() {
        let base = actor.next_available_at(start_time);
        let next_at = schedule_from(actor, base, rng);
        heap.push(Reverse((next_at, idx)));
    }
    heap
}

fn schedule_after(
    actor: &ActorProfile,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> DateTime<Utc> {
    let rate = effective_rate(actor, now, rng);
    let mut next = now + sample_interval(rate, rng);
    if let Some(end) = actor.session_end_at {
        if next > end {
            next = end;
        }
    }
    actor.next_available_at(next)
}

fn schedule_from(
    actor: &ActorProfile,
    base: DateTime<Utc>,
    rng: &mut impl Rng,
) -> DateTime<Utc> {
    let rate = effective_rate(actor, base, rng);
    let next = base + sample_interval(rate, rng);
    actor.next_available_at(next)
}

fn sample_interval(rate_per_hour: f64, rng: &mut impl Rng) -> Duration {
    let rate = rate_per_hour.max(0.001);
    let lambda = rate / 3600.0;
    let u: f64 = rng.gen_range(0.0..1.0);
    let secs = -u.ln() / lambda;
    Duration::milliseconds((secs * 1000.0).max(1.0) as i64)
}

fn effective_rate(actor: &ActorProfile, now: DateTime<Utc>, rng: &mut impl Rng) -> f64 {
    let base = actor.seed.rate_per_hour.max(0.1);
    if matches!(actor.seed.kind, ActorKind::Human) {
        return base;
    }

    let pattern = actor
        .seed
        .service_pattern
        .as_ref()
        .unwrap_or(&ServicePattern::Constant);
    match pattern {
        ServicePattern::Constant => base,
        ServicePattern::Diurnal => base * diurnal_multiplier(actor, now),
        ServicePattern::Bursty => base * burst_multiplier(rng),
    }
}

fn diurnal_multiplier(actor: &ActorProfile, now: DateTime<Utc>) -> f64 {
    let offset = Duration::hours(actor.seed.timezone_offset as i64);
    let local = now + offset;
    let hour = local.hour();
    match hour {
        7..=9 => 0.7,
        10..=17 => 1.1,
        18..=21 => 0.8,
        _ => 0.35,
    }
}

fn burst_multiplier(rng: &mut impl Rng) -> f64 {
    if rng.gen_bool(0.12) {
        rng.gen_range(2.0..5.0)
    } else {
        rng.gen_range(0.4..1.0)
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
    distribution: Option<&Vec<f64>>,
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
        base_regions = defaults;
    }

    let weights = weights_for_regions(&base_regions, distribution);

    let index = WeightedIndex::new(weights).unwrap_or_else(|_| {
        let weights = vec![1.0; base_regions.len()];
        WeightedIndex::new(weights).expect("fallback weights")
    });

    RegionSelector {
        regions: base_regions,
        weights: index,
    }
}

fn weights_for_regions(
    regions: &[String],
    distribution: Option<&Vec<f64>>,
) -> Vec<f64> {
    let Some(distribution) = distribution else {
        return vec![1.0; regions.len()];
    };
    if distribution.len() != regions.len() {
        return vec![1.0; regions.len()];
    }
    let mut weights = Vec::with_capacity(regions.len());
    for weight in distribution {
        if weight.is_finite() && *weight > 0.0 {
            weights.push(*weight);
        } else {
            weights.push(1.0);
        }
    }
    weights
}

fn shuffle_actors(actors: &mut [ActorProfile], rng: &mut impl Rng) {
    for idx in (1..actors.len()).rev() {
        let swap_idx = rng.gen_range(0..=idx);
        actors.swap(idx, swap_idx);
    }
}
