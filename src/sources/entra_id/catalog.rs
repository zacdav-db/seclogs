use rand::distributions::{Distribution, WeightedIndex};
use rand::Rng;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct WeightedEvent {
    pub name: String,
    pub weight: f64,
}

pub fn curated_signin_events() -> Vec<WeightedEvent> {
    vec![
        WeightedEvent {
            name: "SignIn".to_string(),
            weight: 1.0,
        },
        WeightedEvent {
            name: "RefreshToken".to_string(),
            weight: 0.4,
        },
        WeightedEvent {
            name: "DeviceCode".to_string(),
            weight: 0.2,
        },
    ]
}

pub fn curated_audit_events() -> Vec<WeightedEvent> {
    vec![
        WeightedEvent {
            name: "AddUser".to_string(),
            weight: 0.8,
        },
        WeightedEvent {
            name: "UpdateUser".to_string(),
            weight: 1.2,
        },
        WeightedEvent {
            name: "DeleteUser".to_string(),
            weight: 0.2,
        },
        WeightedEvent {
            name: "AddGroupMember".to_string(),
            weight: 0.9,
        },
        WeightedEvent {
            name: "RemoveGroupMember".to_string(),
            weight: 0.4,
        },
        WeightedEvent {
            name: "AddAppRoleAssignment".to_string(),
            weight: 0.6,
        },
        WeightedEvent {
            name: "ResetPassword".to_string(),
            weight: 0.3,
        },
        WeightedEvent {
            name: "UpdateConditionalAccess".to_string(),
            weight: 0.2,
        },
    ]
}

pub fn pick_weighted_event(
    rng: &mut impl Rng,
    candidates: &[WeightedEvent],
    event_bias: &HashMap<String, f64>,
) -> Option<String> {
    let mut names = Vec::new();
    let mut weights = Vec::new();
    for event in candidates {
        if !event.weight.is_finite() || event.weight <= 0.0 {
            continue;
        }
        let mut weight = event.weight;
        if let Some(bias) = event_bias.get(&event.name) {
            if bias.is_finite() && *bias > 0.0 {
                weight *= *bias;
            }
        }
        names.push(event.name.clone());
        weights.push(weight);
    }
    if names.is_empty() {
        return None;
    }
    let index = WeightedIndex::new(weights).ok()?;
    Some(names[index.sample(rng)].clone())
}
