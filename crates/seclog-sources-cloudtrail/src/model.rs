use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTrailEvent {
    pub event_version: String,
    pub event_time: String,
    pub event_source: String,
    pub event_name: String,
    pub aws_region: String,
    pub source_ip_address: String,
    pub user_agent: String,
    pub user_identity: UserIdentity,
    pub request_parameters: Option<Value>,
    pub response_elements: Option<Value>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub event_id: String,
    pub recipient_account_id: String,
    pub read_only: Option<bool>,
}

impl CloudTrailEvent {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    pub identity_type: String,
    pub principal_id: String,
    pub arn: String,
    pub account_id: String,
    pub user_name: Option<String>,
}
