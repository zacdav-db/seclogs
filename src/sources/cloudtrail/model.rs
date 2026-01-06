use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudTrailEvent {
    pub event_version: String,
    pub user_identity: UserIdentity,
    pub event_time: String,
    pub event_source: String,
    pub event_name: String,
    pub aws_region: String,
    #[serde(rename = "sourceIPAddress")]
    pub source_ip_address: String,
    pub user_agent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_parameters: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_elements: Option<Value>,
    #[serde(rename = "requestID")]
    pub request_id: String,
    #[serde(rename = "eventID")]
    pub event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub management_event: Option<bool>,
    pub recipient_account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_details: Option<TlsDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_credential_from_console: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl CloudTrailEvent {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdentity {
    #[serde(rename = "type")]
    pub identity_type: String,
    pub principal_id: String,
    pub arn: String,
    pub account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_context: Option<SessionContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionContext {
    pub session_issuer: Value,
    pub web_id_federation_data: Value,
    pub attributes: SessionAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionAttributes {
    pub creation_date: String,
    pub mfa_authenticated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsDetails {
    pub tls_version: String,
    pub cipher_suite: String,
    pub client_provided_host_header: String,
}
