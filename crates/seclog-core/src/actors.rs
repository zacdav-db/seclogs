use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use rand::distributions::{Distribution, WeightedIndex};
use rand::Rng;
use std::collections::HashSet;

/// High-level actor type used for session behavior and weighting.
#[derive(Debug, Clone)]
pub enum ActorKind {
    Human,
    Service,
}

/// Role label applied to human actors.
#[derive(Debug, Clone)]
pub enum ActorRole {
    Admin,
    Developer,
    ReadOnly,
    Auditor,
}

/// Stable actor attributes used to create runtime profiles.
#[derive(Debug, Clone)]
pub struct ActorSeed {
    pub kind: ActorKind,
    pub role: Option<ActorRole>,
    pub identity_type: String,
    pub principal_id: String,
    pub arn: String,
    pub account_id: String,
    pub user_name: Option<String>,
    pub user_agents: Vec<String>,
    pub source_ips: Vec<String>,
    pub active_start_hour: u8,
    pub active_hours: u8,
    pub timezone_offset: i8,
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

impl ActorPopulation {
    /// Generates a mixed population of human and service actors.
    pub fn generate(
        rng: &mut impl Rng,
        total: usize,
        service_ratio: f64,
        role_weights: &[(ActorRole, f64)],
        account_ids: &[String],
    ) -> Self {
        let total = total.max(1);
        let service_count = ((total as f64) * service_ratio.clamp(0.0, 1.0)).round() as usize;
        let human_count = total.saturating_sub(service_count);
        let mut actors = Vec::with_capacity(total);

        for _ in 0..human_count {
            let account_id = pick_account_id(rng, account_ids);
            actors.push(ActorSeed::new_human(rng, role_weights, &account_id));
        }
        for _ in 0..service_count {
            let account_id = pick_account_id(rng, account_ids);
            actors.push(ActorSeed::new_service(rng, &account_id));
        }

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

impl ActorSeed {
    fn new_human(
        rng: &mut impl Rng,
        role_weights: &[(ActorRole, f64)],
        account_id: &str,
    ) -> Self {
        let user_name = format!("user-{}", random_alpha(rng, 6).to_lowercase());
        let principal_id = format!("AIDA{}", random_alpha(rng, 16));
        let arn = format!("arn:aws:iam::{}:user/{}", account_id, user_name);
        let user_agents = human_user_agents(rng);
        let role = pick_human_role(rng, role_weights);
        let active_hours = rng.gen_range(7..11);
        let active_start_hour = rng.gen_range(6..12);
        let timezone_offset = pick_timezone_offset(rng);
        let weekend_active = rng.gen_bool(0.2);
        Self {
            kind: ActorKind::Human,
            role: Some(role),
            identity_type: "IAMUser".to_string(),
            principal_id,
            arn,
            account_id: account_id.to_string(),
            user_name: Some(user_name),
            user_agents,
            source_ips: human_source_ips(rng),
            active_start_hour,
            active_hours,
            timezone_offset,
            weekend_active,
        }
    }

    fn new_service(rng: &mut impl Rng, account_id: &str) -> Self {
        let role_name = format!("svc-role-{}", random_alpha(rng, 4).to_lowercase());
        let session_name = format!("svc-{}", random_alpha(rng, 8));
        let principal_id = format!("AROA{}", random_alpha(rng, 16));
        let arn = format!(
            "arn:aws:sts::{}:assumed-role/{}/{}",
            account_id, role_name, session_name
        );
        let user_agents = service_user_agents(rng);
        let active_hours = rng.gen_range(16..24);
        let active_start_hour = rng.gen_range(0..24);
        Self {
            kind: ActorKind::Service,
            role: None,
            identity_type: "AssumedRole".to_string(),
            principal_id,
            arn,
            account_id: account_id.to_string(),
            user_name: None,
            user_agents,
            source_ips: service_source_ips(rng),
            active_start_hour,
            active_hours,
            timezone_offset: 0,
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

fn pick_account_id(rng: &mut impl Rng, account_ids: &[String]) -> String {
    if account_ids.is_empty() {
        return "000000000000".to_string();
    }
    let idx = rng.gen_range(0..account_ids.len());
    account_ids[idx].clone()
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
    if !seed.weekend_active && is_weekend(now) {
        return false;
    }

    if seed.active_hours >= 24 {
        return true;
    }

    let local_hour = local_hour(now, seed.timezone_offset);
    let start = seed.active_start_hour;
    let end = (start + seed.active_hours) % 24;
    if start < end {
        local_hour >= start && local_hour < end
    } else {
        local_hour >= start || local_hour < end
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

fn local_hour(now: DateTime<Utc>, offset: i8) -> u8 {
    let hour = now.hour() as i32 + offset as i32;
    hour.rem_euclid(24) as u8
}

fn is_weekend(now: DateTime<Utc>) -> bool {
    let day = now.weekday().number_from_monday();
    day >= 6
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
