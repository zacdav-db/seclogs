use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub envelope: EventEnvelope,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub schema_version: String,
    pub timestamp: String,
    pub source: String,
    pub event_type: String,
    pub actor: Actor,
    pub target: Option<Target>,
    pub outcome: Outcome,
    pub geo: Option<Geo>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub id: String,
    pub kind: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub kind: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Geo {
    pub country: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}
