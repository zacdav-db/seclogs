use super::catalog::{curated_audit_events, curated_signin_events, pick_weighted_event, WeightedEvent};
use super::templates::{build_audit_event, build_signin_event, stable_guid, EntraActorContext};
use crate::core::actors::{ActorKind, ActorProfile};
use crate::core::config::EntraIdSourceConfig;
use crate::core::event::{Actor, Event, EventEnvelope, Outcome, Target};
use crate::core::traits::EventSource;
use chrono::{DateTime, Duration, SecondsFormat, Timelike, Utc};
use rand::distributions::{Distribution, WeightedIndex};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// Entra ID event source with sign-in and audit events.
pub struct EntraIdGenerator {
    rng: StdRng,
    actors: Vec<ActorProfile>,
    schedule: BinaryHeap<Reverse<(DateTime<Utc>, usize)>>,
    category_selector: CategorySelector,
    signin_events: Vec<WeightedEvent>,
    audit_events: Vec<WeightedEvent>,
    tenant_id: String,
    tenant_domain: String,
}

impl EntraIdGenerator {
    pub fn from_config(
        config: &EntraIdSourceConfig,
        mut actors: Vec<ActorProfile>,
        seed: Option<u64>,
        start_time: DateTime<Utc>,
    ) -> Result<Self, EntraConfigError> {
        let mut rng = match seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        };
        shuffle_actors(&mut actors, &mut rng);
        let schedule = build_schedule(&actors, start_time, &mut rng);
        let category_selector = CategorySelector::from_config(config)?;
        Ok(Self {
            rng,
            actors,
            schedule,
            category_selector,
            signin_events: curated_signin_events(),
            audit_events: curated_audit_events(),
            tenant_id: config.tenant_id.clone(),
            tenant_domain: config.tenant_domain.clone(),
        })
    }
}

impl EventSource for EntraIdGenerator {
    fn next_event(&mut self) -> Option<Event> {
        loop {
            let Reverse((now, actor_index)) = self.schedule.pop()?;
            if !self.actors[actor_index].is_available(now, &mut self.rng) {
                let next_at = self.actors[actor_index].next_available_at(now);
                self.schedule.push(Reverse((next_at, actor_index)));
                continue;
            }

            let event_time = now.to_rfc3339_opts(SecondsFormat::Millis, true);
            let (event_type, payload, outcome, target, actor_ctx, last_event) = {
                let actor = &mut self.actors[actor_index];
                actor.ensure_session(now, &mut self.rng);
                let category = self.category_selector.pick(&mut self.rng);
                let error_rate = actor.seed.error_rate;
                let actor_ctx = actor_context(
                    actor,
                    &self.tenant_id,
                    &self.tenant_domain,
                    &mut self.rng,
                );
                match category.as_str() {
                    "audit" => {
                        let activity = pick_weighted_event(
                            &mut self.rng,
                            &self.audit_events,
                            &actor.seed.event_bias,
                        )
                        .unwrap_or_else(|| "UpdateUser".to_string());
                        let audit = build_audit_event(
                            &actor_ctx,
                            &event_time,
                            &mut self.rng,
                            &activity,
                            error_rate,
                        );
                        let outcome = if audit.result == "failure" {
                            Outcome::Failure
                        } else {
                            Outcome::Success
                        };
                        let target = audit
                            .target_resources
                            .first()
                            .map(|resource| Target {
                                id: resource.id.clone(),
                                kind: resource.resource_type.clone(),
                                name: Some(resource.display_name.clone()),
                            });
                        (
                            activity.clone(),
                            audit.to_value(),
                            outcome,
                            target,
                            actor_ctx,
                            activity,
                        )
                    }
                    _ => {
                        let signin_name = pick_weighted_event(
                            &mut self.rng,
                            &self.signin_events,
                            &actor.seed.event_bias,
                        )
                        .unwrap_or_else(|| "SignIn".to_string());
                        let signin = build_signin_event(
                            &actor_ctx,
                            &event_time,
                            &mut self.rng,
                            error_rate,
                            &signin_name,
                        );
                        let outcome = if signin.status.error_code == 0 {
                            Outcome::Success
                        } else {
                            Outcome::Failure
                        };
                        (
                            signin_name.clone(),
                            signin.to_value(),
                            outcome,
                            None,
                            actor_ctx,
                            signin_name,
                        )
                    }
                }
            };

            let actor_id = actor_ctx
                .user_id
                .clone()
                .unwrap_or_else(|| actor_ctx.service_principal_id.clone());
            let actor_name = actor_ctx
                .user_principal_name
                .clone()
                .or_else(|| Some(actor_ctx.app_display_name.clone()));
            let actor_kind = match actor_ctx.kind {
                ActorKind::Human => "user".to_string(),
                ActorKind::Service => "service_principal".to_string(),
            };

            let envelope = EventEnvelope {
                schema_version: "v1".to_string(),
                timestamp: event_time,
                source: "entra_id".to_string(),
                event_type: event_type.clone(),
                actor: Actor {
                    id: actor_id,
                    kind: actor_kind,
                    name: actor_name,
                },
                target,
                outcome,
                geo: None,
                ip: Some(actor_ctx.ip_address.clone()),
                user_agent: Some(actor_ctx.user_agent.clone()),
                session_id: None,
                tenant_id: Some(self.tenant_id.clone()),
            };

            {
                let actor = &mut self.actors[actor_index];
                actor.last_event = Some(last_event);
                actor.consume_session(&mut self.rng);
                let next_at = schedule_after(actor, now, &mut self.rng);
                self.schedule.push(Reverse((next_at, actor_index)));
            }

            return Some(Event {
                envelope,
                payload,
            });
        }
    }
}

#[derive(Debug)]
pub struct EntraConfigError(pub String);

impl std::fmt::Display for EntraConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "entra config error: {}", self.0)
    }
}

impl std::error::Error for EntraConfigError {}

struct CategorySelector {
    categories: Vec<String>,
    weights: WeightedIndex<f64>,
}

impl CategorySelector {
    fn from_config(config: &EntraIdSourceConfig) -> Result<Self, EntraConfigError> {
        let categories = config
            .categories
            .clone()
            .unwrap_or_else(|| vec!["signin".to_string(), "audit".to_string()])
            .into_iter()
            .map(|entry| entry.trim().to_lowercase())
            .filter(|entry| !entry.is_empty())
            .collect::<Vec<String>>();
        if categories.is_empty() {
            return Err(EntraConfigError("no categories configured".to_string()));
        }

        let weights = weights_for_categories(&categories, config.category_weights.as_ref());
        let index = WeightedIndex::new(weights)
            .map_err(|_| EntraConfigError("invalid category weights".to_string()))?;
        Ok(Self {
            categories,
            weights: index,
        })
    }

    fn pick(&self, rng: &mut impl Rng) -> String {
        let idx = self.weights.sample(rng);
        self.categories[idx].clone()
    }
}

fn weights_for_categories(categories: &[String], weights: Option<&Vec<f64>>) -> Vec<f64> {
    let Some(weights) = weights else {
        return vec![1.0; categories.len()];
    };
    if weights.len() != categories.len() {
        return vec![1.0; categories.len()];
    }
    weights
        .iter()
        .map(|weight| if weight.is_finite() && *weight > 0.0 { *weight } else { 1.0 })
        .collect()
}

fn actor_context(
    actor: &mut ActorProfile,
    tenant_id: &str,
    tenant_domain: &str,
    rng: &mut impl Rng,
) -> EntraActorContext {
    let user_agent = actor.current_user_agent(rng);
    let is_interactive = matches!(actor.seed.kind, ActorKind::Human);
    let user_name = actor
        .seed
        .user_name
        .clone()
        .unwrap_or_else(|| format!("user-{}", actor.seed.principal_id.to_lowercase()))
        .to_lowercase();
    let user_principal = format!("{}@{}", user_name, tenant_domain.to_lowercase());
    let user_id = stable_guid(&actor.seed.principal_id, tenant_id);
    let app_id = stable_guid(&actor.seed.access_key_id, tenant_id);
    let service_principal_id = stable_guid(&format!("{}-sp", actor.seed.principal_id), tenant_id);
    let app_display_name = service_app_display_name(actor);
    let service_principal_name = format!(
        "{}@{}",
        app_display_name.to_lowercase().replace(' ', ""),
        tenant_domain.to_lowercase()
    );
    EntraActorContext {
        kind: actor.seed.kind.clone(),
        tenant_id: tenant_id.to_string(),
        tenant_domain: tenant_domain.to_string(),
        user_principal_name: if actor.seed.kind == ActorKind::Human {
            Some(user_principal)
        } else {
            None
        },
        user_display_name: if actor.seed.kind == ActorKind::Human {
            Some(user_name)
        } else {
            None
        },
        user_id: if actor.seed.kind == ActorKind::Human {
            Some(user_id)
        } else {
            None
        },
        app_id,
        app_display_name,
        service_principal_id,
        service_principal_name,
        ip_address: actor.current_source_ip(rng),
        user_agent,
        timezone_offset: actor.seed.timezone_offset,
        is_interactive,
    }
}

fn service_app_display_name(actor: &ActorProfile) -> String {
    match actor.seed.kind {
        ActorKind::Human => "Microsoft 365".to_string(),
        ActorKind::Service => match actor.seed.service_profile {
            Some(crate::core::actors::ServiceProfile::Ec2Reaper) => "EC2 Reaper".to_string(),
            Some(crate::core::actors::ServiceProfile::DataLakeBot) => "Datalake Bot".to_string(),
            Some(crate::core::actors::ServiceProfile::LogsShipper) => "Logs Shipper".to_string(),
            Some(crate::core::actors::ServiceProfile::MetricsCollector) => {
                "Metrics Collector".to_string()
            }
            _ => "Service Principal".to_string(),
        },
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

fn schedule_after(actor: &ActorProfile, now: DateTime<Utc>, rng: &mut impl Rng) -> DateTime<Utc> {
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
        .unwrap_or(&crate::core::actors::ServicePattern::Constant);
    match pattern {
        crate::core::actors::ServicePattern::Constant => base,
        crate::core::actors::ServicePattern::Diurnal => base * diurnal_multiplier(actor, now),
        crate::core::actors::ServicePattern::Bursty => base * burst_multiplier(rng),
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

fn shuffle_actors(actors: &mut [ActorProfile], rng: &mut impl Rng) {
    for idx in (1..actors.len()).rev() {
        let swap_idx = rng.gen_range(0..=idx);
        actors.swap(idx, swap_idx);
    }
}
