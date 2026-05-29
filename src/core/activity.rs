//! Shared identity-backed activity scheduling.
//!
//! These helpers keep identity-registry-backed sources aligned with the actor
//! population model without requiring each source to recreate CloudTrail's
//! actor scheduler.

use crate::core::identity::Identity;
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};

const MIN_RATE_PER_HOUR: f64 = 0.001;

/// Returns the first scheduled baseline event time for an identity.
pub fn first_identity_event_at(
    identity: &Identity,
    start_time: DateTime<Utc>,
    source_salt: &str,
) -> DateTime<Utc> {
    next_identity_event_after(identity, start_time, 0, source_salt)
}

/// Returns the next scheduled baseline event after the supplied timestamp.
pub fn next_identity_event_after(
    identity: &Identity,
    after: DateTime<Utc>,
    sequence: usize,
    source_salt: &str,
) -> DateTime<Utc> {
    let rate = effective_rate_per_hour(identity, after, sequence, source_salt);
    after + deterministic_interval(identity, source_salt, sequence, rate)
}

/// Returns the configured or inferred UTC offset for identity local-time logic.
pub fn identity_timezone_offset(identity: &Identity) -> i8 {
    if let Some(offset) = identity.timezone_offset {
        return offset;
    }

    let region_text = identity_region_text(identity);
    if region_text.contains("singapore") {
        8
    } else if region_text.contains("australia") || region_text.contains("sydney") {
        10
    } else if region_text.contains("tokyo") || region_text.contains("japan") {
        9
    } else if region_text.contains("india") || region_text.contains("bangalore") {
        5
    } else if region_text.contains("united kingdom")
        || region_text.contains("london")
        || region_text.contains("ireland")
    {
        0
    } else if region_text.contains("germany")
        || region_text.contains("france")
        || region_text.contains("netherlands")
    {
        1
    } else if region_text.contains("new york")
        || region_text.contains("east coast")
        || region_text.contains("us-east")
    {
        -5
    } else if region_text.contains("california")
        || region_text.contains("san francisco")
        || region_text.contains("los angeles")
        || region_text.contains("us-west")
    {
        -8
    } else {
        0
    }
}

/// Returns true when the identity is in its configured local active window.
pub fn identity_in_active_window(identity: &Identity, now: DateTime<Utc>) -> bool {
    let local = local_time(identity, now);
    if !identity_weekend_active(identity) && is_weekend_date(local.date_naive()) {
        return false;
    }
    within_active_hour(identity, local.hour() as u8)
}

/// Returns the positive base actor rate for an identity.
pub fn identity_base_rate_per_hour(identity: &Identity) -> f64 {
    identity
        .rate_per_hour
        .filter(|rate| rate.is_finite() && *rate > 0.0)
        .unwrap_or_else(|| default_rate_for_identity(identity))
}

fn effective_rate_per_hour(
    identity: &Identity,
    now: DateTime<Utc>,
    sequence: usize,
    source_salt: &str,
) -> f64 {
    let base = identity_base_rate_per_hour(identity);
    let multiplier = if identity.service_account {
        service_multiplier(identity, now, sequence, source_salt)
    } else {
        human_multiplier(identity, now)
    };
    (base * multiplier).max(MIN_RATE_PER_HOUR)
}

fn default_rate_for_identity(identity: &Identity) -> f64 {
    if identity.service_account {
        return 12.0;
    }
    let role = identity.role_persona.to_ascii_lowercase();
    if role.contains("admin") {
        18.0
    } else if role.contains("audit") || role.contains("risk") || role.contains("security") {
        6.0
    } else if role.contains("read") || role.contains("business") || role.contains("support") {
        8.0
    } else {
        14.0
    }
}

fn human_multiplier(identity: &Identity, now: DateTime<Utc>) -> f64 {
    let local = local_time(identity, now);
    let weekend = is_weekend_date(local.date_naive());
    let active_hour = within_active_hour(identity, local.hour() as u8);
    match (weekend, identity_weekend_active(identity), active_hour) {
        (true, false, _) => 0.035,
        (true, true, true) => 0.65,
        (true, true, false) => 0.10,
        (false, _, true) => 1.8,
        (false, _, false) => 0.12,
    }
}

fn service_multiplier(
    identity: &Identity,
    now: DateTime<Utc>,
    sequence: usize,
    source_salt: &str,
) -> f64 {
    match identity
        .service_pattern
        .as_deref()
        .unwrap_or("constant")
        .to_ascii_lowercase()
        .as_str()
    {
        "diurnal" => diurnal_multiplier(identity, now),
        "bursty" => burst_multiplier(identity, sequence, source_salt),
        _ => 1.0,
    }
}

fn diurnal_multiplier(identity: &Identity, now: DateTime<Utc>) -> f64 {
    let local = local_time(identity, now);
    match local.hour() {
        7..=9 => 0.7,
        10..=17 => 1.1,
        18..=21 => 0.8,
        _ => 0.35,
    }
}

fn burst_multiplier(identity: &Identity, sequence: usize, source_salt: &str) -> f64 {
    let hash = stable_hash(&format!(
        "{}:{source_salt}:burst:{}",
        identity.actor_id, sequence
    ));
    let unit = unit_interval(hash);
    if hash % 100 < 12 {
        2.0 + unit * 3.0
    } else {
        0.4 + unit * 0.6
    }
}

fn deterministic_interval(
    identity: &Identity,
    source_salt: &str,
    sequence: usize,
    rate_per_hour: f64,
) -> Duration {
    let rate = rate_per_hour.max(MIN_RATE_PER_HOUR);
    let hash = stable_hash(&format!(
        "{}:{source_salt}:interval:{sequence}",
        identity.actor_id
    ));
    let unit = unit_interval(hash);
    let lambda = rate / 3600.0;
    let secs = -unit.ln() / lambda;
    Duration::milliseconds((secs * 1000.0).round().clamp(1.0, i64::MAX as f64) as i64)
}

fn local_time(identity: &Identity, now: DateTime<Utc>) -> DateTime<Utc> {
    now + Duration::hours(identity_timezone_offset(identity) as i64)
}

fn within_active_hour(identity: &Identity, local_hour: u8) -> bool {
    let active_hours = identity_active_hours(identity);
    if active_hours >= 24 {
        return true;
    }

    let start = identity_active_start_hour(identity);
    let end = (start + active_hours) % 24;
    if start < end {
        local_hour >= start && local_hour < end
    } else {
        local_hour >= start || local_hour < end
    }
}

fn identity_active_start_hour(identity: &Identity) -> u8 {
    identity
        .active_start_hour
        .filter(|hour| *hour < 24)
        .unwrap_or(if identity.service_account { 0 } else { 8 })
}

fn identity_active_hours(identity: &Identity) -> u8 {
    identity
        .active_hours
        .filter(|hours| *hours > 0 && *hours <= 24)
        .unwrap_or(if identity.service_account { 24 } else { 10 })
}

fn identity_weekend_active(identity: &Identity) -> bool {
    identity.weekend_active.unwrap_or(identity.service_account)
}

fn identity_region_text(identity: &Identity) -> String {
    let mut values = identity.normal_countries_regions.clone();
    values.push(identity.home_location.clone());
    values.join(" ").to_ascii_lowercase()
}

fn is_weekend_date(date: chrono::NaiveDate) -> bool {
    let day = date.weekday().number_from_monday();
    day >= 6
}

fn unit_interval(hash: u64) -> f64 {
    ((hash % 1_000_000) as f64 + 1.0) / 1_000_001.0
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::identity::AwsPrincipal;

    #[test]
    fn human_active_windows_shift_by_region() {
        let singapore = identity("sg", &["Singapore"], Some(8));
        let london = identity("ldn", &["United Kingdom"], Some(0));
        let utc_midday = DateTime::parse_from_rfc3339("2026-01-05T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        assert!(!identity_in_active_window(&singapore, utc_midday));
        assert!(identity_in_active_window(&london, utc_midday));
    }

    #[test]
    fn generated_schedule_prefers_local_active_hours() {
        let identity = identity("sg", &["Singapore"], Some(8));
        let start = DateTime::parse_from_rfc3339("2026-01-05T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut current = start;
        let mut active = 0;
        let mut off_hours = 0;
        for sequence in 0..300 {
            current = next_identity_event_after(&identity, current, sequence, "test");
            if identity_in_active_window(&identity, current) {
                active += 1;
            } else {
                off_hours += 1;
            }
        }

        assert!(active > off_hours * 3, "active={active} off={off_hours}");
    }

    fn identity(actor_id: &str, regions: &[&str], offset: Option<i8>) -> Identity {
        Identity {
            actor_id: actor_id.to_string(),
            email: format!("{actor_id}@example.com"),
            employee_id: format!("E-{actor_id}"),
            display_name: actor_id.to_string(),
            role_persona: "Developer".to_string(),
            department: "Engineering".to_string(),
            home_location: regions.first().copied().unwrap_or("London").to_string(),
            normal_countries_regions: regions.iter().map(|value| (*value).to_string()).collect(),
            okta_user_id: format!("00u{actor_id}"),
            databricks_username: format!("{actor_id}@example.com"),
            aws_principals: vec![AwsPrincipal {
                account_id: "123456789012".to_string(),
                principal_id: format!("AIDA{actor_id}"),
                arn: format!("arn:aws:iam::123456789012:user/{actor_id}"),
                role_name: None,
                role_session_name: None,
                access_key_id: None,
            }],
            service_account: false,
            tags: Vec::new(),
            rate_per_hour: Some(18.0),
            active_start_hour: Some(8),
            active_hours: Some(10),
            timezone_offset: offset,
            weekend_active: Some(false),
            service_pattern: None,
        }
    }
}
