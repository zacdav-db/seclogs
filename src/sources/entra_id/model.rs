use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub struct SignInStatus {
    #[serde(rename = "additionalDetails")]
    pub additional_details: Option<String>,
    #[serde(rename = "errorCode")]
    pub error_code: i32,
    #[serde(rename = "failureReason")]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoCoordinates {
    pub altitude: Option<f64>,
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignInLocation {
    pub city: String,
    pub state: String,
    #[serde(rename = "countryOrRegion")]
    pub country_or_region: String,
    #[serde(rename = "geoCoordinates")]
    pub geo_coordinates: GeoCoordinates,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceDetail {
    pub browser: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "isCompliant")]
    pub is_compliant: Option<bool>,
    #[serde(rename = "isManaged")]
    pub is_managed: Option<bool>,
    #[serde(rename = "operatingSystem")]
    pub operating_system: String,
    #[serde(rename = "trustType")]
    pub trust_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppliedConditionalAccessPolicy {
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "enforcedGrantControls")]
    pub enforced_grant_controls: Vec<String>,
    #[serde(rename = "enforcedSessionControls")]
    pub enforced_session_controls: Vec<String>,
    pub id: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntraSignInEvent {
    pub id: String,
    #[serde(rename = "createdDateTime")]
    pub created_date_time: String,
    #[serde(rename = "appDisplayName")]
    pub app_display_name: String,
    #[serde(rename = "appId")]
    pub app_id: String,
    #[serde(rename = "ipAddress")]
    pub ip_address: String,
    #[serde(rename = "clientAppUsed")]
    pub client_app_used: String,
    #[serde(rename = "correlationId")]
    pub correlation_id: String,
    #[serde(rename = "conditionalAccessStatus")]
    pub conditional_access_status: String,
    #[serde(rename = "appliedConditionalAccessPolicies")]
    pub applied_conditional_access_policies: Vec<AppliedConditionalAccessPolicy>,
    #[serde(rename = "isInteractive")]
    pub is_interactive: bool,
    #[serde(rename = "deviceDetail")]
    pub device_detail: DeviceDetail,
    pub location: SignInLocation,
    #[serde(rename = "riskDetail")]
    pub risk_detail: String,
    #[serde(rename = "riskLevelAggregated")]
    pub risk_level_aggregated: String,
    #[serde(rename = "riskLevelDuringSignIn")]
    pub risk_level_during_sign_in: String,
    #[serde(rename = "riskState")]
    pub risk_state: String,
    #[serde(rename = "riskEventTypes")]
    pub risk_event_types: Vec<String>,
    #[serde(rename = "riskEventTypes_v2")]
    pub risk_event_types_v2: Vec<String>,
    #[serde(rename = "resourceDisplayName")]
    pub resource_display_name: String,
    #[serde(rename = "resourceId")]
    pub resource_id: String,
    pub status: SignInStatus,
    #[serde(rename = "userDisplayName")]
    pub user_display_name: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[serde(rename = "userPrincipalName")]
    pub user_principal_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserIdentity {
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub id: String,
    #[serde(rename = "ipAddress")]
    pub ip_address: String,
    #[serde(rename = "userPrincipalName")]
    pub user_principal_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppIdentity {
    #[serde(rename = "appId")]
    pub app_id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "servicePrincipalId")]
    pub service_principal_id: String,
    #[serde(rename = "servicePrincipalName")]
    pub service_principal_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditActivityInitiator {
    pub app: Option<AppIdentity>,
    pub user: Option<UserIdentity>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModifiedProperty {
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "newValue")]
    pub new_value: Option<String>,
    #[serde(rename = "oldValue")]
    pub old_value: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetResource {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(rename = "userPrincipalName")]
    pub user_principal_name: Option<String>,
    #[serde(rename = "groupType")]
    pub group_type: Option<String>,
    #[serde(rename = "modifiedProperties")]
    pub modified_properties: Vec<ModifiedProperty>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntraAuditEvent {
    #[serde(rename = "activityDateTime")]
    pub activity_date_time: String,
    #[serde(rename = "activityDisplayName")]
    pub activity_display_name: String,
    #[serde(rename = "additionalDetails")]
    pub additional_details: Vec<KeyValue>,
    pub category: String,
    #[serde(rename = "correlationId")]
    pub correlation_id: String,
    pub id: String,
    #[serde(rename = "initiatedBy")]
    pub initiated_by: AuditActivityInitiator,
    #[serde(rename = "loggedByService")]
    pub logged_by_service: String,
    #[serde(rename = "operationType")]
    pub operation_type: String,
    pub result: String,
    #[serde(rename = "resultReason")]
    pub result_reason: Option<String>,
    #[serde(rename = "targetResources")]
    pub target_resources: Vec<TargetResource>,
}

impl EntraSignInEvent {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

impl EntraAuditEvent {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}
