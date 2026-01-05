use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Normalized event container with a shared envelope and source-specific payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Common metadata used by sinks and analytics.
    pub envelope: EventEnvelope,
    /// Source-specific payload (CloudTrail, Okta, etc.).
    pub payload: Value,
}

/// Standard envelope fields applied to every event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Schema version for the envelope layout.
    pub schema_version: String,
    /// Event timestamp (RFC3339).
    pub timestamp: String,
    /// Source system identifier (e.g. `cloudtrail`).
    pub source: String,
    /// Source-specific event type name.
    pub event_type: String,
    /// Actor responsible for the event.
    pub actor: Actor,
    /// Optional target entity of the event.
    pub target: Option<Target>,
    /// Outcome of the event (success/failure/unknown).
    pub outcome: Outcome,
    /// Optional geo metadata for the actor.
    pub geo: Option<Geo>,
    /// Optional source IP address.
    pub ip: Option<String>,
    /// Optional user agent string.
    pub user_agent: Option<String>,
    /// Optional session identifier.
    pub session_id: Option<String>,
    /// Optional tenant/account identifier.
    pub tenant_id: Option<String>,
}

/// Actor identity for an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    /// Stable actor identifier.
    pub id: String,
    /// Actor kind (user, service, etc.).
    pub kind: String,
    /// Optional display name.
    pub name: Option<String>,
}

/// Target entity for an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// Stable target identifier.
    pub id: String,
    /// Target kind (resource, policy, etc.).
    pub kind: String,
    /// Optional display name.
    pub name: Option<String>,
}

/// Event outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
    Unknown,
}

/// Geolocation metadata for an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Geo {
    /// Country name or code.
    pub country: String,
    /// Optional region/state.
    pub region: Option<String>,
    /// Optional city.
    pub city: Option<String>,
    /// Optional latitude.
    pub lat: Option<f64>,
    /// Optional longitude.
    pub lon: Option<f64>,
}
