use rand::distributions::WeightedIndex;
use rand::prelude::*;
use crate::core::config::CloudTrailSourceConfig;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct WeightedEvent {
    pub name: String,
    pub weight: f64,
}

#[derive(Debug)]
pub enum CatalogError {
    EmptyEventSet,
    InvalidWeight { name: String, weight: f64 },
    WeightedIndex(rand::distributions::WeightedError),
    Population(String),
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CatalogError::EmptyEventSet => write!(f, "no events available after applying config"),
            CatalogError::InvalidWeight { name, weight } => {
                write!(f, "invalid weight for {name}: {weight}")
            }
            CatalogError::WeightedIndex(err) => write!(f, "invalid event weights: {err}"),
            CatalogError::Population(err) => write!(f, "actor population error: {err}"),
        }
    }
}

impl std::error::Error for CatalogError {}

#[derive(Debug)]
pub struct EventSelector {
    events: Vec<WeightedEvent>,
    index: WeightedIndex<f64>,
}

impl EventSelector {
    pub fn new(events: Vec<WeightedEvent>) -> Result<Self, CatalogError> {
        if events.is_empty() {
            return Err(CatalogError::EmptyEventSet);
        }

        for event in &events {
            if !event.weight.is_finite() || event.weight <= 0.0 {
                return Err(CatalogError::InvalidWeight {
                    name: event.name.clone(),
                    weight: event.weight,
                });
            }
        }

        let weights: Vec<f64> = events.iter().map(|event| event.weight).collect();
        let index = WeightedIndex::new(&weights).map_err(CatalogError::WeightedIndex)?;

        Ok(Self { events, index })
    }

    pub fn choose<'a, R: Rng + ?Sized>(&'a self, rng: &mut R) -> &'a WeightedEvent {
        let idx = self.index.sample(rng);
        &self.events[idx]
    }
}

pub fn resolve_event_weights(
    config: &CloudTrailSourceConfig,
) -> Result<Vec<WeightedEvent>, CatalogError> {
    let mut events = HashMap::<String, f64>::new();

    if config.curated {
        for (name, weight) in curated_event_weights() {
            events.insert(name.to_string(), weight);
        }
    }

    let mut resolved = Vec::with_capacity(events.len());
    for (name, weight) in events {
        if !weight.is_finite() || weight <= 0.0 {
            return Err(CatalogError::InvalidWeight { name, weight });
        }
        resolved.push(WeightedEvent { name, weight });
    }

    if resolved.is_empty() {
        return Err(CatalogError::EmptyEventSet);
    }

    resolved.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(resolved)
}

pub fn resolve_selector(
    config: &CloudTrailSourceConfig,
) -> Result<EventSelector, CatalogError> {
    let events = resolve_event_weights(config)?;
    EventSelector::new(events)
}

fn curated_event_weights() -> Vec<(&'static str, f64)> {
    vec![
        ("ConsoleLogin", 1.0),
        ("AssumeRole", 0.8),
        ("GetSessionToken", 0.6),
        ("GetCallerIdentity", 0.6),
        ("CreateUser", 0.3),
        ("DeleteUser", 0.1),
        ("CreateAccessKey", 0.2),
        ("UpdateAccessKey", 0.2),
        ("AttachRolePolicy", 0.2),
        ("PutObject", 1.4),
        ("GetObject", 1.6),
        ("DeleteObject", 0.8),
        ("CreateBucket", 0.3),
        ("DeleteBucket", 0.1),
        ("RunInstances", 0.4),
        ("TerminateInstances", 0.2),
        ("StartInstances", 0.3),
        ("StopInstances", 0.3),
        ("DescribeInstances", 0.9),
        ("CreateSecurityGroup", 0.3),
        ("AuthorizeSecurityGroupIngress", 0.4),
        ("CreateLogGroup", 0.2),
        ("PutLogEvents", 1.1),
        ("CreateLogStream", 0.5),
        ("DescribeLogStreams", 0.6),
        ("Encrypt", 0.5),
        ("Decrypt", 0.5),
        ("GenerateDataKey", 0.4),
        ("PutMetricData", 0.8),
        ("GetMetricData", 0.8),
        ("ListMetrics", 0.5),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::CloudTrailSourceConfig;

    #[test]
    fn curated_only() {
        let config = CloudTrailSourceConfig {
            curated: true,
            actor_population_path: None,
            regions: None,
            region_distribution: None,
        };

        let resolved = resolve_event_weights(&config).expect("curated events");
        assert!(resolved.iter().any(|event| event.name == "ConsoleLogin"));
    }

}
