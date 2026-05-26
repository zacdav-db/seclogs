use crate::core::config::{OktaOutcomeResult, OktaSeverity, OktaTransactionType};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Okta System Log `LogEvent` shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaLogEvent {
    pub actor: OktaActor,
    pub authentication_context: OktaAuthenticationContext,
    pub client: OktaClient,
    pub debug_context: OktaDebugContext,
    pub display_message: String,
    pub event_type: String,
    pub legacy_event_type: Option<String>,
    pub outcome: OktaOutcome,
    pub published: String,
    pub request: OktaRequest,
    pub security_context: OktaSecurityContext,
    pub severity: OktaSeverity,
    pub target: Vec<OktaTarget>,
    pub transaction: OktaTransaction,
    pub uuid: String,
    pub version: String,
}

impl OktaLogEvent {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaActor {
    pub alternate_id: String,
    pub detail_entry: Value,
    pub display_name: String,
    pub id: String,
    #[serde(rename = "type")]
    pub actor_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaAuthenticationContext {
    pub authentication_provider: Option<String>,
    pub authentication_step: i32,
    pub credential_provider: Option<String>,
    pub credential_type: Option<String>,
    pub external_session_id: String,
    #[serde(rename = "interface")]
    pub interface_name: Option<String>,
    pub issuer: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaClient {
    pub device: Option<String>,
    pub geographical_context: OktaGeographicalContext,
    pub id: Option<String>,
    pub ip_address: String,
    pub user_agent: OktaUserAgent,
    pub zone: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaDebugContext {
    pub debug_data: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaGeographicalContext {
    pub city: Option<String>,
    pub country: Option<String>,
    pub geolocation: Value,
    pub postal_code: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaIpChainEntry {
    pub geographical_context: OktaGeographicalContext,
    pub ip: String,
    pub ip_details: Value,
    pub source: Option<String>,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaOutcome {
    pub reason: Option<String>,
    pub result: OktaOutcomeResult,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaRequest {
    pub ip_chain: Vec<OktaIpChainEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaSecurityContext {
    pub as_number: Option<i64>,
    pub as_org: Option<String>,
    pub bot_protection: Value,
    pub domain: Option<String>,
    pub ip_details: Value,
    pub isp: Option<String>,
    pub is_proxy: Option<bool>,
    pub risk: Value,
    pub user_behaviors: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaTarget {
    pub alternate_id: Option<String>,
    pub change_details: Value,
    pub detail_entry: Value,
    pub display_name: Option<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub target_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaTransaction {
    pub detail: Value,
    pub id: String,
    #[serde(rename = "type")]
    pub transaction_type: OktaTransactionType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OktaUserAgent {
    pub browser: Option<String>,
    pub os: Option<String>,
    pub raw_user_agent: String,
}
