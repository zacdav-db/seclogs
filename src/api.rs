//! Programmatic generation API used by language bindings.

use crate::core::actors::generate_population;
use crate::core::config::{Config, MultiSourceConfig, PopulationConfig, SourceConfig};
use crate::core::event::Event;
use crate::core::identity::IdentityRegistry;
use crate::core::traits::EventSource;
use crate::sources::cloudtrail::CloudTrailGenerator;
use crate::sources::composite::CompositeEventSource;
use crate::sources::databricks::DatabricksAuditGenerator;
use crate::sources::okta::OktaSystemLogGenerator;
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;

pub type ApiResult<T> = Result<T, Box<dyn Error>>;

/// Generate normalized events from a loaded config.
pub fn generate_events(config: &Config, max_events: Option<usize>) -> ApiResult<Vec<Event>> {
    let mut stream = EventStream::from_config(config)?;
    let limit = max_events.unwrap_or(100);
    let mut events = Vec::with_capacity(limit);

    for _ in 0..limit {
        let Some(event) = stream.next_event() else {
            break;
        };
        events.push(event);
    }

    Ok(events)
}

/// Stateful event stream for language bindings and other library callers.
pub struct EventStream {
    source: Box<dyn EventSource>,
}

impl EventStream {
    pub fn from_config(config: &Config) -> ApiResult<Self> {
        let start_time = parse_start_time(config.traffic.start_time.as_deref())?;
        let source = build_event_source(&config.source, config.seed, start_time)?;
        Ok(Self { source })
    }

    pub fn from_json(config_json: &str) -> ApiResult<Self> {
        let config: Config = serde_json::from_str(config_json)?;
        Self::from_config(&config)
    }

    pub fn from_toml(config_toml: &str) -> ApiResult<Self> {
        let config: Config = toml::from_str(config_toml)?;
        Self::from_config(&config)
    }

    pub fn next_event(&mut self) -> Option<Event> {
        self.source.next_event()
    }

    pub fn next_event_json(&mut self) -> ApiResult<Option<String>> {
        self.next_event()
            .map(|event| Ok(serde_json::to_string(&event)?))
            .transpose()
    }

    pub fn next_batch_json(&mut self, max_events: usize) -> ApiResult<Vec<String>> {
        let mut events = Vec::with_capacity(max_events);
        for _ in 0..max_events {
            let Some(event) = self.next_event_json()? else {
                break;
            };
            events.push(event);
        }
        Ok(events)
    }
}

/// Generate JSON-serialized normalized events from a JSON config string.
pub fn generate_events_json(
    config_json: &str,
    max_events: Option<usize>,
) -> ApiResult<Vec<String>> {
    let config: Config = serde_json::from_str(config_json)?;
    generate_events(&config, max_events)?
        .into_iter()
        .map(|event| Ok(serde_json::to_string(&event)?))
        .collect()
}

/// Generate JSON-serialized normalized events from a TOML config string.
pub fn generate_events_toml(
    config_toml: &str,
    max_events: Option<usize>,
) -> ApiResult<Vec<String>> {
    let config: Config = toml::from_str(config_toml)?;
    generate_events(&config, max_events)?
        .into_iter()
        .map(|event| Ok(serde_json::to_string(&event)?))
        .collect()
}

/// Generate JSON-serialized identities from a JSON population config string.
pub fn generate_identities_json(population_json: &str) -> ApiResult<Vec<String>> {
    let config: PopulationConfig = serde_json::from_str(population_json)?;
    let population = generate_population(&config)?;
    let registry = IdentityRegistry::from_population("generated_identity_registry", &population)?;
    registry
        .identities()
        .iter()
        .map(|identity| Ok(serde_json::to_string(identity)?))
        .collect()
}

/// Generate JSON-serialized identities from a TOML population config string.
pub fn generate_identities_toml(population_toml: &str) -> ApiResult<Vec<String>> {
    let config: PopulationConfig = toml::from_str(population_toml)?;
    let population = generate_population(&config)?;
    let registry = IdentityRegistry::from_population("generated_identity_registry", &population)?;
    registry
        .identities()
        .iter()
        .map(|identity| Ok(serde_json::to_string(identity)?))
        .collect()
}

/// Convert a TOML generator config to its JSON representation.
pub fn config_toml_to_json(config_toml: &str) -> ApiResult<String> {
    let config: Config = toml::from_str(config_toml)?;
    Ok(serde_json::to_string(&config)?)
}

/// Convert a TOML population config to its JSON representation.
pub fn population_toml_to_json(population_toml: &str) -> ApiResult<String> {
    let config: PopulationConfig = toml::from_str(population_toml)?;
    Ok(serde_json::to_string(&config)?)
}

pub fn build_event_source(
    config: &SourceConfig,
    seed: Option<u64>,
    start_time: DateTime<Utc>,
) -> ApiResult<Box<dyn EventSource>> {
    build_event_source_with_registry(config, seed, start_time, None)
}

fn build_event_source_with_registry(
    config: &SourceConfig,
    seed: Option<u64>,
    start_time: DateTime<Utc>,
    inherited_registry: Option<&IdentityRegistry>,
) -> ApiResult<Box<dyn EventSource>> {
    match config {
        SourceConfig::CloudTrail(config) => {
            if let Some(registry) = inherited_registry {
                if config.actor_population_path.is_none() && config.identity_registry_path.is_none()
                {
                    return Ok(Box::new(CloudTrailGenerator::from_registry(
                        config,
                        registry.clone(),
                        seed,
                        start_time,
                    )?));
                }
            }
            Ok(Box::new(CloudTrailGenerator::from_config(
                config, seed, start_time,
            )?))
        }
        SourceConfig::DatabricksAudit(config) => {
            if let Some(registry) = inherited_registry {
                if config.identity_registry_path.trim().is_empty() {
                    return Ok(Box::new(DatabricksAuditGenerator::from_registry(
                        config,
                        registry.clone(),
                        start_time,
                    )?));
                }
            }
            Ok(Box::new(DatabricksAuditGenerator::from_config(
                config, start_time,
            )?))
        }
        SourceConfig::OktaSystemLog(config) => {
            if let Some(registry) = inherited_registry {
                if config.identity_registry_path.trim().is_empty() {
                    return Ok(Box::new(OktaSystemLogGenerator::from_registry(
                        config,
                        registry.clone(),
                        start_time,
                    )?));
                }
            }
            Ok(Box::new(OktaSystemLogGenerator::from_config(
                config, start_time,
            )?))
        }
        SourceConfig::Multi(config) => {
            build_multi_event_source(config, seed, start_time, inherited_registry)
        }
    }
}

fn build_multi_event_source(
    config: &MultiSourceConfig,
    seed: Option<u64>,
    start_time: DateTime<Utc>,
    inherited_registry: Option<&IdentityRegistry>,
) -> ApiResult<Box<dyn EventSource>> {
    if config.sources.is_empty() {
        return Err(invalid_input(
            "multi source requires at least one child source",
        ));
    }
    let generated_registry = shared_registry_for_multi(config)?;
    let registry = generated_registry.as_ref().or(inherited_registry);
    let mut sources = Vec::with_capacity(config.sources.len());

    for (idx, source) in config.sources.iter().enumerate() {
        let source = inherit_identity_registry(source, config.identity_registry_path.as_deref());
        let child_seed = seed.map(|seed| seed.wrapping_add(idx as u64));
        sources.push(build_event_source_with_registry(
            &source, child_seed, start_time, registry,
        )?);
    }

    Ok(Box::new(CompositeEventSource::new(sources)))
}

fn shared_registry_for_multi(config: &MultiSourceConfig) -> ApiResult<Option<IdentityRegistry>> {
    let identity_registry_path = config
        .identity_registry_path
        .as_deref()
        .and_then(non_empty_str);
    let population_config_path = config
        .population_config_path
        .as_deref()
        .and_then(non_empty_str);
    let inline_population_config = config.population_config.as_ref();

    let configured_count = [
        identity_registry_path.is_some(),
        population_config_path.is_some(),
        inline_population_config.is_some(),
    ]
    .into_iter()
    .filter(|configured| *configured)
    .count();
    if configured_count > 1 {
        return Err(invalid_input(
            "multi source can set only one of identity_registry_path, population_config_path, or population_config",
        ));
    }

    if population_config_path.is_some() || inline_population_config.is_some() {
        let mut child_registry_paths = BTreeSet::new();
        for source in &config.sources {
            collect_identity_registry_paths(source, None, &mut child_registry_paths)?;
        }
        if !child_registry_paths.is_empty() {
            return Err(invalid_input(format!(
                "multi source with generated population cannot also set child identity_registry_path values: {}",
                child_registry_paths.into_iter().collect::<Vec<_>>().join(", ")
            )));
        }
    }

    if let Some(path) = identity_registry_path {
        return Ok(Some(IdentityRegistry::from_path(path)?));
    }
    if let Some(path) = population_config_path {
        return Ok(Some(identity_registry_from_population_config(
            &PopulationConfig::from_path(path)?,
        )?));
    }
    if let Some(config) = inline_population_config {
        return Ok(Some(identity_registry_from_population_config(config)?));
    }

    Ok(None)
}

fn identity_registry_from_population_config(
    config: &PopulationConfig,
) -> ApiResult<IdentityRegistry> {
    let population = generate_population(config)?;
    Ok(IdentityRegistry::from_population(
        "generated_identity_registry",
        &population,
    )?)
}

fn inherit_identity_registry(config: &SourceConfig, path: Option<&str>) -> SourceConfig {
    let mut inherited = config.clone();
    let Some(path) = path.and_then(non_empty_str) else {
        return inherited;
    };

    match &mut inherited {
        SourceConfig::CloudTrail(config) => {
            if config.actor_population_path.is_none() && config.identity_registry_path.is_none() {
                config.identity_registry_path = Some(path.to_string());
            }
        }
        SourceConfig::DatabricksAudit(config) => {
            if config.identity_registry_path.trim().is_empty() {
                config.identity_registry_path = path.to_string();
            }
        }
        SourceConfig::OktaSystemLog(config) => {
            if config.identity_registry_path.trim().is_empty() {
                config.identity_registry_path = path.to_string();
            }
        }
        SourceConfig::Multi(config) => {
            if config.identity_registry_path.is_none() {
                config.identity_registry_path = Some(path.to_string());
            }
        }
    }

    inherited
}

fn collect_identity_registry_paths(
    config: &SourceConfig,
    inherited_path: Option<&str>,
    paths: &mut BTreeSet<String>,
) -> ApiResult<()> {
    match config {
        SourceConfig::CloudTrail(config) => {
            insert_optional_path(
                paths,
                config
                    .identity_registry_path
                    .as_deref()
                    .and_then(non_empty_str)
                    .or(inherited_path),
            );
        }
        SourceConfig::DatabricksAudit(config) => {
            insert_optional_path(
                paths,
                non_empty_str(&config.identity_registry_path).or(inherited_path),
            );
        }
        SourceConfig::OktaSystemLog(config) => {
            insert_optional_path(
                paths,
                non_empty_str(&config.identity_registry_path).or(inherited_path),
            );
        }
        SourceConfig::Multi(config) => {
            let next_inherited = config
                .identity_registry_path
                .as_deref()
                .and_then(non_empty_str)
                .or(inherited_path);
            for source in &config.sources {
                collect_identity_registry_paths(source, next_inherited, paths)?;
            }
        }
    }
    Ok(())
}

fn insert_optional_path(paths: &mut BTreeSet<String>, value: Option<&str>) {
    if let Some(value) = value.and_then(non_empty_str) {
        paths.insert(value.to_string());
    }
}

fn parse_start_time(value: Option<&str>) -> ApiResult<DateTime<Utc>> {
    match value {
        Some(value) => Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc)),
        None => Ok(Utc::now()),
    }
}

fn non_empty_str(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn invalid_input(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generate_events_json_accepts_inline_population_config() {
        let config = json!({
            "seed": 7,
            "traffic": {
                "start_time": "2026-01-01T00:00:00Z",
                "time_scale": 36000.0
            },
            "output": {
                "dir": "./out-test",
                "files": {
                    "target_size_mb": 50,
                    "max_age_seconds": 10
                },
                "format": {
                    "type": "jsonl",
                    "compression": null
                }
            },
            "source": {
                "type": "multi",
                "population_config": population_config_json(),
                "sources": [
                    {
                        "type": "cloudtrail",
                        "curated": true,
                        "regions": ["us-east-1"],
                        "region_distribution": [1.0]
                    },
                    {
                        "type": "databricks_audit",
                        "account_id": "example-account-id",
                        "workspace_id": "1234567890",
                        "baseline_events_per_actor": 1
                    },
                    {
                        "type": "okta",
                        "org_id": "okta-example-org",
                        "baseline_events_per_actor": 1
                    }
                ]
            }
        });

        let events = generate_events_json(&config.to_string(), Some(3)).unwrap();
        assert_eq!(events.len(), 3);

        for event in events {
            let event: serde_json::Value = serde_json::from_str(&event).unwrap();
            assert!(event["envelope"]["actor"]["id"].as_str().is_some());
            assert!(event["payload"].is_object());
        }
    }

    fn population_config_json() -> serde_json::Value {
        json!({
            "seed": 42,
            "timezone_distribution": [
                {"name": "America/Los_Angeles", "weight": 0.7},
                {"name": "Europe/London", "weight": 0.3}
            ],
            "population": {
                "actor_count": 6,
                "service_ratio": 0.2,
                "hot_actor_ratio": 0.05,
                "hot_actor_multiplier": 6.0,
                "account_ids": ["123456789012"],
                "error_rate": {
                    "min": 0.01,
                    "max": 0.04,
                    "distribution": "uniform"
                },
                "human_error_rate": {
                    "min": 0.02,
                    "max": 0.06,
                    "distribution": "normal"
                },
                "service_error_rate": {
                    "min": 0.005,
                    "max": 0.02,
                    "distribution": "uniform"
                },
                "role": [
                    {
                        "name": "admin",
                        "weight": 0.2,
                        "events_per_hour": 24.0
                    },
                    {
                        "name": "developer",
                        "weight": 0.8,
                        "events_per_hour": 18.0
                    }
                ],
                "service_profiles": [
                    {
                        "name": "logs_shipper",
                        "weight": 1.0,
                        "events_per_hour": 20.0,
                        "pattern": "constant"
                    }
                ]
            }
        })
    }
}
