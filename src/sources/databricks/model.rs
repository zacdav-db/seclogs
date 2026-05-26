use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Row-shaped representation of `system.access.audit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabricksAuditEvent {
    pub account_id: String,
    pub workspace_id: String,
    pub version: String,
    pub event_time: String,
    pub event_date: String,
    pub source_ip_address: String,
    pub user_agent: String,
    pub session_id: String,
    pub user_identity: DatabricksUserIdentity,
    pub service_name: String,
    pub action_name: String,
    pub request_id: String,
    pub request_params: BTreeMap<String, String>,
    pub response: DatabricksResponse,
    pub audit_level: String,
    pub event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_metadata: Option<DatabricksIdentityMetadata>,
}

impl DatabricksAuditEvent {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabricksUserIdentity {
    pub email: String,
    pub subject_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabricksResponse {
    pub status_code: i32,
    pub error_message: Option<String>,
    pub result: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabricksIdentityMetadata {
    pub run_by: Option<String>,
    pub run_as: Option<String>,
    pub acting_resource: Option<String>,
    pub run_by_display_name: Option<String>,
    pub run_as_display_name: Option<String>,
}
