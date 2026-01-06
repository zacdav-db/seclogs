use chrono::{offset::Offset, DateTime, Datelike, Duration, TimeZone, Timelike, Utc};
use chrono_tz::Tz;
use rand::distributions::{Distribution, WeightedIndex};
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use crate::config::{
    ErrorRateConfig, ErrorRateDistribution, ExplicitActorConfig, PopulationActorsConfig,
    PopulationConfig, RoleConfig, ServicePatternConfig, ServiceProfileConfig, TimezoneWeight,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

/// High-level actor type used for session behavior and weighting.
#[derive(Debug, Clone)]
pub enum ActorKind {
    Human,
    Service,
}

/// Role label applied to human actors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorRole {
    Admin,
    Developer,
    ReadOnly,
    Auditor,
}

#[derive(Debug, Clone)]
pub enum ServiceProfile {
    Generic,
    Ec2Reaper,
    DataLakeBot,
    LogsShipper,
    MetricsCollector,
}

#[derive(Debug, Clone)]
pub enum ServicePattern {
    Constant,
    Diurnal,
    Bursty,
}

#[derive(Debug)]
pub struct ActorConfigError(pub String);

impl std::fmt::Display for ActorConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "actor config error: {}", self.0)
    }
}

impl std::error::Error for ActorConfigError {}

/// Stable actor attributes used to create runtime profiles.
#[derive(Debug, Clone)]
pub struct ActorSeed {
    pub kind: ActorKind,
    pub role: Option<ActorRole>,
    pub id: Option<String>,
    pub identity_type: String,
    pub principal_id: String,
    pub arn: String,
    pub account_id: String,
    pub access_key_id: String,
    pub rate_per_hour: f64,
    pub error_rate: f64,
    pub tags: Vec<String>,
    pub event_bias: HashMap<String, f64>,
    pub service_profile: Option<ServiceProfile>,
    pub service_pattern: Option<ServicePattern>,
    pub user_name: Option<String>,
    pub user_agents: Vec<String>,
    pub source_ips: Vec<String>,
    pub active_start_hour: u8,
    pub active_hours: u8,
    pub timezone_offset: i8,
    pub timezone_fixed: bool,
    pub weekend_active: bool,
}

/// Mutable runtime state for an actor across event generation.
#[derive(Debug, Clone)]
pub struct ActorProfile {
    /// Stable actor attributes.
    pub seed: ActorSeed,
    /// Previous event name for sequence-aware selection.
    pub last_event: Option<String>,
    /// Remaining events in the current session.
    pub session_remaining: u8,
    /// Session end time in UTC.
    pub session_end_at: Option<DateTime<Utc>>,
    /// Next session start time in UTC.
    pub next_session_at: Option<DateTime<Utc>>,
    /// Sticky user agent for the current session.
    pub session_user_agent: Option<String>,
    /// Sticky source IP for the current session.
    pub session_source_ip: Option<String>,
}

impl ActorProfile {
    /// Builds a fresh profile from a seed with no active session.
    pub fn from_seed(seed: ActorSeed) -> Self {
        Self {
            seed,
            last_event: None,
            session_remaining: 0,
            session_end_at: None,
            next_session_at: None,
            session_user_agent: None,
            session_source_ip: None,
        }
    }

    /// Returns whether the actor can emit events at the given time.
    ///
    /// This updates session boundaries and cooldowns when a session ends.
    pub fn is_available(&mut self, now: DateTime<Utc>, rng: &mut impl Rng) -> bool {
        if let Some(end) = self.session_end_at {
            if now >= end {
                self.session_end_at = None;
                self.last_event = None;
                self.session_remaining = 0;
                self.session_user_agent = None;
                self.session_source_ip = None;
                let cooldown = cooldown_minutes(&self.seed.kind, rng);
                self.next_session_at = Some(now + Duration::minutes(cooldown));
            }
        }

        if !within_active_window(&self.seed, now) {
            return false;
        }

        if let Some(next) = self.next_session_at {
            if now < next {
                return false;
            }
        }

        true
    }

    /// Starts or resumes a session if needed and chooses session-level UA/IP.
    pub fn ensure_session(&mut self, now: DateTime<Utc>, rng: &mut impl Rng) {
        if let Some(next) = self.next_session_at {
            if now >= next {
                self.next_session_at = None;
            }
        }

        if self.session_end_at.is_none() {
            self.last_event = None;
            let minutes = session_minutes(&self.seed.kind, rng);
            self.session_end_at = Some(now + Duration::minutes(minutes));
            self.session_user_agent = Some(self.pick_user_agent(rng));
            self.session_source_ip = Some(self.pick_source_ip(rng));
        }

        if self.session_remaining == 0 {
            self.session_remaining = session_event_count(&self.seed.kind, rng);
        }
    }

    /// Consumes one event in the current session.
    pub fn consume_session(&mut self, rng: &mut impl Rng) {
        if self.session_remaining > 0 {
            self.session_remaining -= 1;
        }
        if self.session_remaining == 0 && rng.gen_bool(0.2) {
            self.last_event = None;
        }
    }

    /// Returns the session user agent, sampling a new one if needed.
    pub fn current_user_agent(&mut self, rng: &mut impl Rng) -> String {
        if self.session_user_agent.is_none() {
            self.session_user_agent = Some(self.pick_user_agent(rng));
        }
        self.session_user_agent
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Returns the session source IP, sampling a new one if needed.
    pub fn current_source_ip(&mut self, rng: &mut impl Rng) -> String {
        if self.session_source_ip.is_none() {
            self.session_source_ip = Some(self.pick_source_ip(rng));
        }
        self.session_source_ip
            .clone()
            .unwrap_or_else(|| "0.0.0.0".to_string())
    }

    /// Returns the next time this actor can emit an event.
    pub fn next_available_at(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        let mut candidate = now;
        if let Some(next) = self.next_session_at {
            if next > candidate {
                candidate = next;
            }
        }

        if within_active_window(&self.seed, candidate) {
            return candidate;
        }

        next_active_window_start(&self.seed, candidate)
    }

    fn pick_user_agent(&self, rng: &mut impl Rng) -> String {
        let primary_weight = match self.seed.kind {
            ActorKind::Human => 0.65,
            ActorKind::Service => 0.9,
        };
        pick_sticky(&self.seed.user_agents, primary_weight, rng)
    }

    fn pick_source_ip(&self, rng: &mut impl Rng) -> String {
        let primary_weight = match self.seed.kind {
            ActorKind::Human => 0.7,
            ActorKind::Service => 0.95,
        };
        pick_sticky(&self.seed.source_ips, primary_weight, rng)
    }
}

/// Collection of actor seeds that can be reused across sources.
#[derive(Debug, Clone)]
pub struct ActorPopulation {
    pub actors: Vec<ActorSeed>,
}

pub struct RoleRates {
    pub admin: f64,
    pub developer: f64,
    pub readonly: f64,
    pub auditor: f64,
}

impl RoleRates {
    pub fn default() -> Self {
        Self {
            admin: 24.0,
            developer: 18.0,
            readonly: 8.0,
            auditor: 6.0,
        }
    }

    pub fn for_role(&self, role: &ActorRole) -> f64 {
        match role {
            ActorRole::Admin => self.admin,
            ActorRole::Developer => self.developer,
            ActorRole::ReadOnly => self.readonly,
            ActorRole::Auditor => self.auditor,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ErrorRateSpec {
    pub min: f64,
    pub max: f64,
    pub distribution: ErrorRateDistribution,
}

#[derive(Debug, Clone)]
pub struct ServiceProfileSpec {
    pub profile: ServiceProfile,
    pub weight: f64,
    pub rate_per_hour: f64,
    pub pattern: ServicePattern,
}

pub struct PopulationSpec<'a> {
    pub total: usize,
    pub service_ratio: f64,
    pub role_weights: &'a [(ActorRole, f64)],
    pub role_rates: &'a RoleRates,
    pub service_rate_per_hour: f64,
    pub service_profiles: &'a [ServiceProfileSpec],
    pub hot_actor_ratio: f64,
    pub hot_actor_multiplier: f64,
    pub human_error_rate: ErrorRateSpec,
    pub service_error_rate: ErrorRateSpec,
    pub account_ids: &'a [String],
}

impl ActorPopulation {
    /// Generates a mixed population of human and service actors.
    pub fn generate(rng: &mut impl Rng, spec: &PopulationSpec<'_>) -> Self {
        let total = spec.total;
        if total == 0 {
            return Self { actors: Vec::new() };
        }
        let service_count =
            ((total as f64) * spec.service_ratio.clamp(0.0, 1.0)).round() as usize;
        let human_count = total.saturating_sub(service_count);
        let mut actors = Vec::with_capacity(total);

        for _ in 0..human_count {
            let account_id = pick_account_id(rng, spec.account_ids);
            let error_rate = sample_error_rate(rng, spec.human_error_rate);
            actors.push(ActorSeed::new_human(
                rng,
                spec.role_weights,
                spec.role_rates,
                &account_id,
                error_rate,
            ));
        }
        for _ in 0..service_count {
            let account_id = pick_account_id(rng, spec.account_ids);
            let profile = pick_service_profile(rng, spec.service_profiles, spec.service_rate_per_hour);
            let error_rate = sample_error_rate(rng, spec.service_error_rate);
            actors.push(ActorSeed::new_service(
                rng,
                &account_id,
                profile.profile,
                profile.pattern,
                profile.rate_per_hour,
                error_rate,
            ));
        }

        apply_hot_actor_rates(rng, &mut actors, spec.hot_actor_ratio, spec.hot_actor_multiplier);
        Self { actors }
    }

    /// Creates runtime profiles with session state for each actor.
    pub fn profiles(&self) -> Vec<ActorProfile> {
        self.actors
            .iter()
            .cloned()
            .map(ActorProfile::from_seed)
            .collect()
    }
}

/// Builds an actor population from the dedicated population config.
pub fn generate_population(
    config: &PopulationConfig,
) -> Result<ActorPopulation, ActorConfigError> {
    let mut rng = match config.seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_entropy(),
    };
    let population = &config.population;
    let service_ratio = population.service_ratio.unwrap_or(0.2).clamp(0.0, 1.0);
    let hot_actor_ratio = population.hot_actor_ratio.unwrap_or(0.1).clamp(0.0, 1.0);
    let hot_actor_multiplier = population.hot_actor_multiplier.unwrap_or(6.0).max(1.0);
    let (role_weights, role_rates) = build_role_config(population.role.as_ref());
    let account_ids = build_account_pool(population);
    let service_rate = population
        .service_events_per_hour
        .unwrap_or(6.0)
        .max(0.1);
    let service_profiles =
        build_service_profiles(population.service_profiles.as_ref(), service_rate);
    let baseline_error = error_rate_spec(
        population.error_rate.as_ref(),
        default_error_rate_spec(),
    );
    let human_error = error_rate_spec(population.human_error_rate.as_ref(), baseline_error);
    let service_error = error_rate_spec(population.service_error_rate.as_ref(), baseline_error);
    let start_time = Utc::now();
    let explicit = build_explicit_actors(
        &mut rng,
        population.actor.as_ref(),
        human_error,
        service_error,
        &account_ids,
        start_time,
    )?;
    let total = population
        .actor_count
        .unwrap_or(500)
        .max(explicit.len())
        .max(1);
    let remaining = total.saturating_sub(explicit.len());

    let spec = PopulationSpec {
        total: remaining,
        service_ratio,
        role_weights: &role_weights,
        role_rates: &role_rates,
        service_rate_per_hour: service_rate,
        service_profiles: &service_profiles,
        hot_actor_ratio,
        hot_actor_multiplier,
        human_error_rate: human_error,
        service_error_rate: service_error,
        account_ids: &account_ids,
    };

    let mut population = ActorPopulation::generate(&mut rng, &spec);
    population.actors.extend(explicit);
    apply_timezone_distribution(
        &mut population,
        config.timezone_distribution.as_ref(),
        start_time,
        &mut rng,
    );
    Ok(population)
}

fn build_explicit_actors(
    rng: &mut impl Rng,
    entries: Option<&Vec<ExplicitActorConfig>>,
    human_error: ErrorRateSpec,
    service_error: ErrorRateSpec,
    account_ids: &[String],
    start_time: DateTime<Utc>,
) -> Result<Vec<ActorSeed>, ActorConfigError> {
    let Some(entries) = entries else {
        return Ok(Vec::new());
    };
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let mut actors = Vec::with_capacity(entries.len());
    let mut ids = HashSet::new();
    for entry in entries {
        let id = entry.id.trim();
        if id.is_empty() {
            return Err(ActorConfigError(
                "population.actor id must be non-empty".to_string(),
            ));
        }
        if !ids.insert(id.to_string()) {
            return Err(ActorConfigError(format!(
                "population.actor id is duplicated: {id}"
            )));
        }

        let kind = parse_actor_kind(&entry.kind, id)?;
        let events_per_hour = require_events_per_hour(entry.events_per_hour, id)?;
        let error_rate = match entry.error_rate {
            Some(rate) => validate_error_rate(rate, id)?,
            None => match kind {
                ActorKind::Human => sample_error_rate(rng, human_error),
                ActorKind::Service => sample_error_rate(rng, service_error),
            },
        };
        let account_id = match &entry.account_id {
            Some(value) => validate_account_id(value, id)?,
            None => pick_account_id(rng, account_ids),
        };
        let tags = normalize_tags(&entry.tags);
        let event_bias = normalize_event_bias(&entry.event_bias);

        let mut actor = match kind {
            ActorKind::Human => {
                if entry.service_profile.is_some() {
                    return Err(ActorConfigError(format!(
                        "population.actor {id} is human but service_profile is set"
                    )));
                }
                let role_name = entry.role.as_deref().ok_or_else(|| {
                    ActorConfigError(format!(
                        "population.actor {id} is human but role is missing"
                    ))
                })?;
                let role = parse_actor_role(role_name, id)?;
                let mut override_rates = RoleRates::default();
                match role {
                    ActorRole::Admin => override_rates.admin = events_per_hour,
                    ActorRole::Developer => override_rates.developer = events_per_hour,
                    ActorRole::ReadOnly => override_rates.readonly = events_per_hour,
                    ActorRole::Auditor => override_rates.auditor = events_per_hour,
                }
                let role_weights = vec![(role, 1.0)];
                let mut seed =
                    ActorSeed::new_human(rng, &role_weights, &override_rates, &account_id, error_rate);
                seed.rate_per_hour = events_per_hour;
                if let Some(identity_type) = &entry.identity_type {
                    seed.identity_type = identity_type.clone();
                }
                if let Some(principal_id) = &entry.principal_id {
                    seed.principal_id = principal_id.clone();
                }
                if let Some(name) = &entry.user_name {
                    seed.user_name = Some(name.clone());
                    if entry.arn.is_none() {
                        seed.arn = format!("arn:aws:iam::{}:user/{}", account_id, name);
                    }
                }
                if let Some(arn) = &entry.arn {
                    seed.arn = arn.clone();
                }
                if let Some(access_key_id) = &entry.access_key_id {
                    seed.access_key_id = access_key_id.clone();
                }
                seed
            }
            ActorKind::Service => {
                if entry.role.is_some() {
                    return Err(ActorConfigError(format!(
                        "population.actor {id} is service but role is set"
                    )));
                }
                if entry.user_name.is_some() {
                    return Err(ActorConfigError(format!(
                        "population.actor {id} is service but user_name is set"
                    )));
                }
                let profile_name = entry.service_profile.as_deref().ok_or_else(|| {
                    ActorConfigError(format!(
                        "population.actor {id} is service but service_profile is missing"
                    ))
                })?;
                let profile = parse_service_profile(profile_name, id)?;
                let pattern = entry
                    .service_pattern
                    .as_ref()
                    .map(service_pattern_from_config)
                    .unwrap_or(ServicePattern::Constant);
                let mut seed =
                    ActorSeed::new_service(rng, &account_id, profile, pattern, events_per_hour, error_rate);
                if let Some(identity_type) = &entry.identity_type {
                    seed.identity_type = identity_type.clone();
                }
                if let Some(principal_id) = &entry.principal_id {
                    seed.principal_id = principal_id.clone();
                }
                if let Some(arn) = &entry.arn {
                    seed.arn = arn.clone();
                }
                if let Some(access_key_id) = &entry.access_key_id {
                    seed.access_key_id = access_key_id.clone();
                }
                seed
            }
        };

        if let Some(user_agents) = &entry.user_agents {
            let list = normalize_string_list(user_agents, id, "user_agents")?;
            actor.user_agents = list;
        }
        if let Some(source_ips) = &entry.source_ips {
            let list = normalize_string_list(source_ips, id, "source_ips")?;
            actor.source_ips = list;
        }
        if let Some(active_start) = entry.active_start_hour {
            if active_start > 23 {
                return Err(ActorConfigError(format!(
                    "population.actor {id} active_start_hour must be 0-23"
                )));
            }
            actor.active_start_hour = active_start;
        }
        if let Some(active_hours) = entry.active_hours {
            if active_hours == 0 || active_hours > 24 {
                return Err(ActorConfigError(format!(
                    "population.actor {id} active_hours must be 1-24"
                )));
            }
            actor.active_hours = active_hours;
        }
        if let Some(weekend_active) = entry.weekend_active {
            actor.weekend_active = weekend_active;
        }
        if let Some(timezone) = &entry.timezone {
            let offset = timezone_offset_for_name(timezone, start_time, id)?;
            actor.timezone_offset = offset;
            actor.timezone_fixed = true;
        }

        actor.id = Some(id.to_string());
        actor.tags = tags;
        actor.event_bias = event_bias;
        actors.push(actor);
    }

    Ok(actors)
}

fn parse_actor_kind(value: &str, id: &str) -> Result<ActorKind, ActorConfigError> {
    match value.trim().to_lowercase().as_str() {
        "human" => Ok(ActorKind::Human),
        "service" => Ok(ActorKind::Service),
        other => Err(ActorConfigError(format!(
            "population.actor {id} has invalid kind: {other}"
        ))),
    }
}

fn parse_actor_role(value: &str, id: &str) -> Result<ActorRole, ActorConfigError> {
    match value.trim().to_lowercase().as_str() {
        "admin" => Ok(ActorRole::Admin),
        "developer" => Ok(ActorRole::Developer),
        "readonly" => Ok(ActorRole::ReadOnly),
        "auditor" => Ok(ActorRole::Auditor),
        other => Err(ActorConfigError(format!(
            "population.actor {id} has invalid role: {other}"
        ))),
    }
}

fn parse_service_profile(value: &str, id: &str) -> Result<ServiceProfile, ActorConfigError> {
    normalize_profile_name(value).ok_or_else(|| {
        ActorConfigError(format!(
            "population.actor {id} has invalid service_profile: {value}"
        ))
    })
}

fn require_events_per_hour(
    value: Option<f64>,
    id: &str,
) -> Result<f64, ActorConfigError> {
    let rate = value.ok_or_else(|| {
        ActorConfigError(format!(
            "population.actor {id} is missing events_per_hour"
        ))
    })?;
    if !rate.is_finite() || rate <= 0.0 {
        return Err(ActorConfigError(format!(
            "population.actor {id} events_per_hour must be > 0"
        )));
    }
    Ok(rate)
}

fn validate_error_rate(rate: f64, id: &str) -> Result<f64, ActorConfigError> {
    if !rate.is_finite() || rate < 0.0 || rate > 1.0 {
        return Err(ActorConfigError(format!(
            "population.actor {id} error_rate must be between 0.0 and 1.0"
        )));
    }
    Ok(rate)
}

fn validate_account_id(value: &str, id: &str) -> Result<String, ActorConfigError> {
    let trimmed = value.trim();
    let valid = trimmed.len() == 12 && trimmed.chars().all(|c| c.is_ascii_digit());
    if !valid {
        return Err(ActorConfigError(format!(
            "population.actor {id} account_id must be a 12-digit string"
        )));
    }
    Ok(trimmed.to_string())
}

fn normalize_string_list(
    list: &[String],
    id: &str,
    field: &str,
) -> Result<Vec<String>, ActorConfigError> {
    let mut values: Vec<String> = list.iter().map(|value| value.trim().to_string()).collect();
    values.retain(|value| !value.is_empty());
    if values.is_empty() {
        return Err(ActorConfigError(format!(
            "population.actor {id} {field} must contain at least one value"
        )));
    }
    Ok(values)
}

fn normalize_tags(tags: &[String]) -> Vec<String> {
    let mut values: Vec<String> = tags.iter().map(|tag| tag.trim().to_string()).collect();
    values.retain(|tag| !tag.is_empty());
    values.sort();
    values.dedup();
    values
}

fn normalize_event_bias(bias: &HashMap<String, f64>) -> HashMap<String, f64> {
    let mut cleaned = HashMap::new();
    for (name, weight) in bias {
        let name = name.trim();
        if name.is_empty() || !weight.is_finite() || *weight <= 0.0 {
            continue;
        }
        cleaned.insert(name.to_string(), *weight);
    }
    cleaned
}

fn timezone_offset_for_name(
    value: &str,
    start_time: DateTime<Utc>,
    id: &str,
) -> Result<i8, ActorConfigError> {
    let tz = Tz::from_str(value.trim()).map_err(|_| {
        ActorConfigError(format!(
            "population.actor {id} timezone must be a valid IANA name"
        ))
    })?;
    let offset_seconds = tz
        .offset_from_utc_datetime(&start_time.naive_utc())
        .fix()
        .local_minus_utc();
    Ok((offset_seconds as f64 / 3600.0).round() as i8)
}

impl ActorSeed {
    fn new_human(
        rng: &mut impl Rng,
        role_weights: &[(ActorRole, f64)],
        role_rates: &RoleRates,
        account_id: &str,
        error_rate: f64,
    ) -> Self {
        let user_name = format!("user-{}", random_alpha(rng, 6).to_lowercase());
        let principal_id = format!("AIDA{}", random_alpha(rng, 16));
        let arn = format!("arn:aws:iam::{}:user/{}", account_id, user_name);
        let access_key_id = random_access_key(rng, "AKIA");
        let user_agents = human_user_agents(rng);
        let role = pick_human_role(rng, role_weights);
        let rate_per_hour = role_rates.for_role(&role);
        let active_hours = rng.gen_range(7..11);
        let active_start_hour = rng.gen_range(6..12);
        let timezone_offset = pick_timezone_offset(rng);
        let weekend_active = rng.gen_bool(0.2);
        Self {
            kind: ActorKind::Human,
            role: Some(role),
            id: None,
            identity_type: "IAMUser".to_string(),
            principal_id,
            arn,
            account_id: account_id.to_string(),
            access_key_id,
            rate_per_hour,
            error_rate,
            tags: Vec::new(),
            event_bias: HashMap::new(),
            service_profile: None,
            service_pattern: None,
            user_name: Some(user_name),
            user_agents,
            source_ips: human_source_ips(rng),
            active_start_hour,
            active_hours,
            timezone_offset,
            timezone_fixed: false,
            weekend_active,
        }
    }

    fn new_service(
        rng: &mut impl Rng,
        account_id: &str,
        profile: ServiceProfile,
        pattern: ServicePattern,
        rate_per_hour: f64,
        error_rate: f64,
    ) -> Self {
        let role_name = format!("svc-role-{}", random_alpha(rng, 4).to_lowercase());
        let session_name = format!("svc-{}", random_alpha(rng, 8));
        let principal_id = format!("AROA{}", random_alpha(rng, 16));
        let arn = format!(
            "arn:aws:sts::{}:assumed-role/{}/{}",
            account_id, role_name, session_name
        );
        let access_key_id = random_access_key(rng, "ASIA");
        let user_agents = service_user_agents(rng);
        let active_hours = rng.gen_range(16..24);
        let active_start_hour = rng.gen_range(0..24);
        Self {
            kind: ActorKind::Service,
            role: None,
            id: None,
            identity_type: "AssumedRole".to_string(),
            principal_id,
            arn,
            account_id: account_id.to_string(),
            access_key_id,
            rate_per_hour,
            error_rate,
            tags: Vec::new(),
            event_bias: HashMap::new(),
            service_profile: Some(profile),
            service_pattern: Some(pattern),
            user_name: None,
            user_agents,
            source_ips: service_source_ips(rng),
            active_start_hour,
            active_hours,
            timezone_offset: 0,
            timezone_fixed: false,
            weekend_active: true,
        }
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

fn pick_service_profile<'a>(
    rng: &mut impl Rng,
    profiles: &'a [ServiceProfileSpec],
    fallback_rate: f64,
) -> ServiceProfileSpec {
    if profiles.is_empty() {
        return ServiceProfileSpec {
            profile: ServiceProfile::Generic,
            weight: 1.0,
            rate_per_hour: fallback_rate.max(0.1),
            pattern: ServicePattern::Constant,
        };
    }

    let weights: Vec<f64> = profiles.iter().map(|profile| profile.weight).collect();
    let index = WeightedIndex::new(weights).ok();
    if let Some(index) = index {
        return profiles[index.sample(rng)].clone();
    }

    profiles[0].clone()
}

fn apply_hot_actor_rates(
    rng: &mut impl Rng,
    actors: &mut [ActorSeed],
    hot_ratio: f64,
    hot_multiplier: f64,
) {
    let ratio = hot_ratio.clamp(0.0, 1.0);
    let hot_count = ((actors.len() as f64) * ratio).round() as usize;
    if hot_count == 0 || actors.is_empty() {
        return;
    }
    let mut indices: Vec<usize> = (0..actors.len()).collect();
    for i in 0..hot_count.min(actors.len()) {
        let swap_idx = rng.gen_range(i..actors.len());
        indices.swap(i, swap_idx);
        let idx = indices[i];
        actors[idx].rate_per_hour *= hot_multiplier.max(1.0);
    }
}

fn pick_account_id(rng: &mut impl Rng, account_ids: &[String]) -> String {
    if account_ids.is_empty() {
        return "000000000000".to_string();
    }
    let idx = rng.gen_range(0..account_ids.len());
    account_ids[idx].clone()
}

fn build_account_pool(config: &PopulationActorsConfig) -> Vec<String> {
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

fn build_role_config(config: Option<&Vec<RoleConfig>>) -> (Vec<(ActorRole, f64)>, RoleRates) {
    let mut weights = vec![
        (ActorRole::Admin, 0.15),
        (ActorRole::Developer, 0.55),
        (ActorRole::ReadOnly, 0.25),
        (ActorRole::Auditor, 0.05),
    ];
    let mut rates = RoleRates::default();

    let entries = match config {
        Some(list) if !list.is_empty() => list,
        _ => return (weights, rates),
    };

    for entry in entries {
        let role = match entry.name.as_str() {
            "admin" => ActorRole::Admin,
            "developer" => ActorRole::Developer,
            "readonly" => ActorRole::ReadOnly,
            "auditor" => ActorRole::Auditor,
            _ => continue,
        };
        let weight = entry.weight;
        if weight.is_finite() && weight > 0.0 {
            if let Some(slot) = weights.iter_mut().find(|(r, _)| *r == role) {
                slot.1 = weight;
            }
        }
        let rate = entry.events_per_hour;
        if rate.is_finite() && rate > 0.0 {
            match role {
                ActorRole::Admin => rates.admin = rate,
                ActorRole::Developer => rates.developer = rate,
                ActorRole::ReadOnly => rates.readonly = rate,
                ActorRole::Auditor => rates.auditor = rate,
            }
        }
    }

    (weights, rates)
}

fn build_service_profiles(
    config: Option<&Vec<ServiceProfileConfig>>,
    fallback_rate: f64,
) -> Vec<ServiceProfileSpec> {
    let entries = match config {
        Some(list) if !list.is_empty() => list,
        _ => return Vec::new(),
    };

    let mut profiles = Vec::new();
    for entry in entries {
        if !entry.weight.is_finite() || entry.weight <= 0.0 {
            continue;
        }
        let profile = match normalize_profile_name(&entry.name) {
            Some(profile) => profile,
            None => continue,
        };
        let rate = entry.events_per_hour.unwrap_or(fallback_rate).max(0.1);
        let pattern = entry
            .pattern
            .as_ref()
            .map(service_pattern_from_config)
            .unwrap_or(ServicePattern::Constant);
        profiles.push(ServiceProfileSpec {
            profile,
            weight: entry.weight,
            rate_per_hour: rate,
            pattern,
        });
    }

    profiles
}

fn default_error_rate_spec() -> ErrorRateSpec {
    ErrorRateSpec {
        min: 0.01,
        max: 0.05,
        distribution: ErrorRateDistribution::Uniform,
    }
}

fn error_rate_spec(config: Option<&ErrorRateConfig>, fallback: ErrorRateSpec) -> ErrorRateSpec {
    let Some(config) = config else {
        return fallback;
    };
    let mut min = config.min;
    let mut max = config.max;
    if !min.is_finite() || !max.is_finite() {
        return fallback;
    }
    min = min.clamp(0.0, 1.0);
    max = max.clamp(0.0, 1.0);
    if max < min {
        std::mem::swap(&mut min, &mut max);
    }
    let distribution = config
        .distribution
        .clone()
        .unwrap_or(ErrorRateDistribution::Uniform);
    ErrorRateSpec {
        min,
        max,
        distribution,
    }
}

fn sample_error_rate(rng: &mut impl Rng, spec: ErrorRateSpec) -> f64 {
    let min = spec.min;
    let max = spec.max;
    if (max - min).abs() <= f64::EPSILON {
        return min;
    }
    match spec.distribution {
        ErrorRateDistribution::Uniform => rng.gen_range(min..=max),
        ErrorRateDistribution::Normal => {
            let mean = (min + max) / 2.0;
            let std = ((max - min) / 6.0).max(0.000_1);
            for _ in 0..6 {
                let value = mean + std * standard_normal(rng);
                if value >= min && value <= max {
                    return value;
                }
            }
            (mean + std * standard_normal(rng)).clamp(min, max)
        }
    }
}

fn standard_normal(rng: &mut impl Rng) -> f64 {
    let u1: f64 = rng.gen_range(0.0..1.0);
    let u2: f64 = rng.gen_range(0.0..1.0);
    (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
}

fn normalize_profile_name(name: &str) -> Option<ServiceProfile> {
    match name.trim().to_lowercase().replace('-', "_").as_str() {
        "generic" => Some(ServiceProfile::Generic),
        "ec2_reaper" => Some(ServiceProfile::Ec2Reaper),
        "datalake_bot" => Some(ServiceProfile::DataLakeBot),
        "logs_shipper" => Some(ServiceProfile::LogsShipper),
        "metrics_collector" => Some(ServiceProfile::MetricsCollector),
        _ => None,
    }
}

fn service_pattern_from_config(value: &ServicePatternConfig) -> ServicePattern {
    match value {
        ServicePatternConfig::Constant => ServicePattern::Constant,
        ServicePatternConfig::Diurnal => ServicePattern::Diurnal,
        ServicePatternConfig::Bursty => ServicePattern::Bursty,
    }
}

fn pick_timezone_offset(rng: &mut impl Rng) -> i8 {
    let roll: f64 = rng.gen();
    if roll < 0.5 {
        -8
    } else if roll < 0.8 {
        0
    } else {
        8
    }
}

fn within_active_window(seed: &ActorSeed, now: DateTime<Utc>) -> bool {
    let offset = Duration::hours(seed.timezone_offset as i64);
    let local = now + offset;
    if !seed.weekend_active && is_weekend_date(local.date_naive()) {
        return false;
    }
    if seed.active_hours >= 24 {
        return true;
    }

    let local_hour = local.hour() as u8;
    let start = seed.active_start_hour;
    let end = (start + seed.active_hours) % 24;
    if start < end {
        local_hour >= start && local_hour < end
    } else {
        local_hour >= start || local_hour < end
    }
}

fn apply_timezone_distribution(
    population: &mut ActorPopulation,
    distribution: Option<&Vec<TimezoneWeight>>,
    start_time: DateTime<Utc>,
    rng: &mut impl Rng,
) {
    let entries = match distribution {
        Some(list) if !list.is_empty() => list,
        _ => return,
    };

    let mut offsets = Vec::new();
    let mut weights = Vec::new();
    for entry in entries {
        if !entry.weight.is_finite() || entry.weight <= 0.0 {
            continue;
        }
        let tz = match Tz::from_str(&entry.name) {
            Ok(tz) => tz,
            Err(_) => continue,
        };
        let offset_seconds = tz
            .offset_from_utc_datetime(&start_time.naive_utc())
            .fix()
            .local_minus_utc();
        let offset_hours = (offset_seconds as f64 / 3600.0).round() as i8;
        offsets.push(offset_hours);
        weights.push(entry.weight);
    }

    if offsets.is_empty() {
        return;
    }

    let index = match WeightedIndex::new(&weights) {
        Ok(index) => index,
        Err(_) => return,
    };

    for actor in &mut population.actors {
        if actor.timezone_fixed {
            continue;
        }
        let choice = index.sample(rng);
        actor.timezone_offset = offsets[choice];
    }
}

fn pick_sticky(values: &[String], primary_weight: f64, rng: &mut impl Rng) -> String {
    if values.is_empty() {
        return "unknown".to_string();
    }
    if values.len() == 1 {
        return values[0].clone();
    }
    if rng.gen_bool(primary_weight) {
        return values[0].clone();
    }
    let idx = rng.gen_range(1..values.len());
    values[idx].clone()
}

fn session_event_count(kind: &ActorKind, rng: &mut impl Rng) -> u8 {
    match kind {
        ActorKind::Human => rng.gen_range(3..10),
        ActorKind::Service => rng.gen_range(6..18),
    }
}

fn session_minutes(kind: &ActorKind, rng: &mut impl Rng) -> i64 {
    match kind {
        ActorKind::Human => rng.gen_range(20..120),
        ActorKind::Service => rng.gen_range(10..60),
    }
}

fn cooldown_minutes(kind: &ActorKind, rng: &mut impl Rng) -> i64 {
    match kind {
        ActorKind::Human => rng.gen_range(30..180),
        ActorKind::Service => rng.gen_range(5..30),
    }
}

fn is_weekend_date(date: chrono::NaiveDate) -> bool {
    let day = date.weekday().number_from_monday();
    day >= 6
}

fn next_active_window_start(seed: &ActorSeed, now: DateTime<Utc>) -> DateTime<Utc> {
    let offset = Duration::hours(seed.timezone_offset as i64);
    let local = now + offset;
    let mut date = local.date_naive();

    loop {
        if !seed.weekend_active && is_weekend_date(date) {
            date = date + Duration::days(1);
            continue;
        }

        let start = match date.and_hms_opt(seed.active_start_hour as u32, 0, 0) {
            Some(value) => value,
            None => {
                date = date + Duration::days(1);
                continue;
            }
        };

        if date > local.date_naive() || local.time() < start.time() {
            let start_utc = start - offset;
            return Utc.from_utc_datetime(&start_utc);
        }

        date = date + Duration::days(1);
    }
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

fn random_access_key(rng: &mut impl Rng, prefix: &str) -> String {
    format!("{}{}", prefix, random_alpha(rng, 16))
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
        0 => format!(
            "10.{}.{}.{}",
            rng.gen_range(0..=255),
            rng.gen_range(0..=255),
            rng.gen_range(1..=254)
        ),
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
            let major = rng.gen_range(123..127);
            format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36",
                major
            )
        }
    }
}

fn random_service_user_agent(rng: &mut impl Rng) -> String {
    match rng.gen_range(0..5) {
        0 => "aws-sdk-go/1.44.2 (go1.20.5; linux; amd64)".to_string(),
        1 => "aws-sdk-java/1.12.500 Linux/5.15.0 OpenJDK_64-Bit_Server_VM/17.0.8".to_string(),
        2 => "aws-sdk-js/2.1400.0 promise".to_string(),
        3 => "aws-sdk-rust/1.0.0 linux/x86_64".to_string(),
        _ => format!(
            "Boto3/1.28.{} Python/3.11.{} Linux/5.15",
            rng.gen_range(10..30),
            rng.gen_range(1..6)
        ),
    }
}

fn human_user_agents(rng: &mut impl Rng) -> Vec<String> {
    let mut unique = HashSet::new();
    let target = rng.gen_range(2..5);
    while unique.len() < target {
        unique.insert(random_human_user_agent(rng));
    }
    let mut list: Vec<String> = unique.into_iter().collect();
    list.sort();
    if list.len() > 1 {
        let idx = rng.gen_range(0..list.len());
        list.swap(0, idx);
    }
    list
}

fn service_user_agents(rng: &mut impl Rng) -> Vec<String> {
    let mut list = vec![random_service_user_agent(rng)];
    if rng.gen_bool(0.2) {
        let other = random_service_user_agent(rng);
        if other != list[0] {
            list.push(other);
        }
    }
    list
}

fn human_source_ips(rng: &mut impl Rng) -> Vec<String> {
    let mut unique = HashSet::new();
    let target = rng.gen_range(1..4);
    while unique.len() < target {
        unique.insert(random_ip(rng));
    }
    let mut list: Vec<String> = unique.into_iter().collect();
    list.sort();
    if list.len() > 1 {
        let idx = rng.gen_range(0..list.len());
        list.swap(0, idx);
    }
    list
}

fn service_source_ips(rng: &mut impl Rng) -> Vec<String> {
    let mut list = vec![random_private_ip(rng)];
    if rng.gen_bool(0.1) {
        let other = random_private_ip(rng);
        if other != list[0] {
            list.push(other);
        }
    }
    list
}
