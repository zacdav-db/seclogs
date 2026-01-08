use crate::core::actors::ActorKind;
use crate::sources::entra_id::model::{
    AppliedConditionalAccessPolicy, AppIdentity, AuditActivityInitiator, DeviceDetail,
    EntraAuditEvent, EntraSignInEvent, GeoCoordinates, KeyValue, ModifiedProperty,
    SignInLocation, SignInStatus, TargetResource, UserIdentity,
};
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone)]
pub struct EntraActorContext {
    pub kind: ActorKind,
    pub tenant_id: String,
    pub tenant_domain: String,
    pub user_principal_name: Option<String>,
    pub user_display_name: Option<String>,
    pub user_id: Option<String>,
    pub app_id: String,
    pub app_display_name: String,
    pub service_principal_id: String,
    pub service_principal_name: String,
    pub ip_address: String,
    pub user_agent: String,
    pub timezone_offset: i8,
    pub is_interactive: bool,
}

pub fn build_signin_event(
    ctx: &EntraActorContext,
    event_time: &str,
    rng: &mut impl Rng,
    error_rate: f64,
    event_name: &str,
) -> EntraSignInEvent {
    let failure = rng.gen_bool(error_rate.clamp(0.0, 1.0));
    let (error_code, failure_reason, additional_details) = if failure {
        let options = [
            (50126, "Invalid username or password"),
            (50053, "Account is locked"),
            (50055, "Password expired"),
            (50057, "User account is disabled"),
        ];
        let choice = rng.gen_range(0..options.len());
        (
            options[choice].0,
            Some(options[choice].1.to_string()),
            Some("Authentication failed".to_string()),
        )
    } else {
        (0, None, Some("MFA requirement satisfied".to_string()))
    };

    let device_detail = device_detail(&ctx.user_agent, rng);
    let location = location_for_offset(ctx.timezone_offset, rng);
    let conditional_access_status = if !failure && rng.gen_bool(0.2) {
        "notApplied".to_string()
    } else if failure {
        "failure".to_string()
    } else {
        "success".to_string()
    };
    let risk_detail = if failure && rng.gen_bool(0.25) {
        "unfamiliarFeatures".to_string()
    } else {
        "none".to_string()
    };
    let risk_level = if risk_detail == "none" {
        "none".to_string()
    } else if rng.gen_bool(0.6) {
        "medium".to_string()
    } else {
        "low".to_string()
    };
    let risk_state = if risk_level == "none" { "none" } else { "atRisk" }.to_string();
    let applied_policies = conditional_access_policies(&conditional_access_status, rng);
    let risk_events = if risk_detail == "none" {
        Vec::new()
    } else {
        vec!["unfamiliarFeatures".to_string()]
    };
    let client_app_used = client_app_used(&ctx.user_agent, ctx.is_interactive, event_name, rng);

    EntraSignInEvent {
        id: random_guid(rng),
        created_date_time: event_time.to_string(),
        app_display_name: ctx.app_display_name.clone(),
        app_id: ctx.app_id.clone(),
        user_display_name: ctx.user_display_name.clone(),
        user_id: ctx.user_id.clone(),
        user_principal_name: ctx.user_principal_name.clone(),
        ip_address: ctx.ip_address.clone(),
        client_app_used,
        correlation_id: random_guid(rng),
        is_interactive: ctx.is_interactive,
        conditional_access_status,
        applied_conditional_access_policies: applied_policies,
        device_detail,
        location,
        risk_detail,
        risk_level_aggregated: risk_level.clone(),
        risk_level_during_sign_in: risk_level,
        risk_state,
        risk_event_types: risk_events.clone(),
        risk_event_types_v2: risk_events,
        resource_display_name: ctx.app_display_name.clone(),
        resource_id: ctx.app_id.clone(),
        status: SignInStatus {
            additional_details,
            error_code,
            failure_reason,
        },
    }
}

pub fn build_audit_event(
    ctx: &EntraActorContext,
    event_time: &str,
    rng: &mut impl Rng,
    activity: &str,
    error_rate: f64,
) -> EntraAuditEvent {
    let failure = rng.gen_bool(error_rate.clamp(0.0, 1.0));
    let (result, reason) = if failure {
        ("failure".to_string(), Some("Operation failed".to_string()))
    } else {
        ("success".to_string(), None)
    };

    let initiated_by = match ctx.kind {
        ActorKind::Human => AuditActivityInitiator {
            user: Some(UserIdentity {
                id: ctx.user_id.clone().unwrap_or_else(|| stable_guid("user", "fallback")),
                display_name: ctx
                    .user_display_name
                    .clone()
                    .unwrap_or_else(|| "Unknown User".to_string()),
                user_principal_name: ctx
                    .user_principal_name
                    .clone()
                    .unwrap_or_else(|| "unknown@domain".to_string()),
                ip_address: ctx.ip_address.clone(),
            }),
            app: None,
        },
        ActorKind::Service => AuditActivityInitiator {
            user: None,
            app: Some(AppIdentity {
                app_id: ctx.app_id.clone(),
                display_name: ctx.app_display_name.clone(),
                service_principal_id: ctx.service_principal_id.clone(),
                service_principal_name: ctx.service_principal_name.clone(),
            }),
        },
    };

    let target = target_resource_for(activity, ctx, rng);

    EntraAuditEvent {
        id: random_guid(rng),
        activity_date_time: event_time.to_string(),
        activity_display_name: activity.to_string(),
        category: audit_category(activity).to_string(),
        additional_details: audit_additional_details(activity),
        correlation_id: random_guid(rng),
        result,
        result_reason: reason,
        logged_by_service: "Core Directory".to_string(),
        operation_type: audit_operation(activity).to_string(),
        initiated_by,
        target_resources: vec![target],
    }
}

pub fn stable_guid(seed: &str, salt: &str) -> String {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    salt.hash(&mut hasher);
    let high = hasher.finish();
    let mut hasher = DefaultHasher::new();
    salt.hash(&mut hasher);
    seed.hash(&mut hasher);
    let low = hasher.finish();
    guid_from_bytes(high.to_be_bytes(), low.to_be_bytes())
}

fn random_guid(rng: &mut impl Rng) -> String {
    let bytes: Vec<u8> = rng
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(|b| b.to_ascii_lowercase())
        .collect();
    let hex = String::from_utf8_lossy(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn guid_from_bytes(high: [u8; 8], low: [u8; 8]) -> String {
    let mut hex = String::with_capacity(32);
    for byte in high.iter().chain(low.iter()) {
        hex.push_str(&format!("{:02x}", byte));
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn base_client_app_used(user_agent: &str, interactive: bool, rng: &mut impl Rng) -> String {
    if !interactive {
        return "Other clients".to_string();
    }
    if user_agent.contains("Mobile") || user_agent.contains("iPhone") {
        return "MobileAppsAndDesktopClients".to_string();
    }
    if rng.gen_bool(0.1) {
        return "Exchange ActiveSync".to_string();
    }
    "Browser".to_string()
}

fn client_app_used(
    user_agent: &str,
    interactive: bool,
    event_name: &str,
    rng: &mut impl Rng,
) -> String {
    match event_name {
        "DeviceCode" => "Other clients".to_string(),
        "RefreshToken" => "Other clients".to_string(),
        _ => base_client_app_used(user_agent, interactive, rng),
    }
}

fn device_detail(user_agent: &str, rng: &mut impl Rng) -> DeviceDetail {
    let operating_system = if user_agent.contains("Windows") {
        "Windows".to_string()
    } else if user_agent.contains("Mac OS") {
        "macOS".to_string()
    } else if user_agent.contains("Linux") {
        "Linux".to_string()
    } else if user_agent.contains("iPhone") {
        "iOS".to_string()
    } else {
        "Unknown".to_string()
    };
    let browser = if user_agent.contains("Chrome/") {
        "Chrome".to_string()
    } else if user_agent.contains("Firefox/") {
        "Firefox".to_string()
    } else if user_agent.contains("Safari/") {
        "Safari".to_string()
    } else {
        "Unknown".to_string()
    };
    let display_name = match operating_system.as_str() {
        "Windows" => "Windows Desktop",
        "macOS" => "MacBook Pro",
        "Linux" => "Linux Workstation",
        "iOS" => "iPhone",
        _ => "Unknown Device",
    }
    .to_string();
    let is_managed = if rng.gen_bool(0.5) { Some(true) } else { Some(false) };
    let is_compliant = is_managed.map(|managed| managed && rng.gen_bool(0.7));
    let trust_type = if is_managed.unwrap_or(false) {
        Some("AzureAD".to_string())
    } else if rng.gen_bool(0.2) {
        Some("HybridAzureADJoined".to_string())
    } else {
        None
    };

    DeviceDetail {
        browser,
        device_id: random_guid(rng),
        display_name,
        is_compliant,
        is_managed,
        operating_system,
        trust_type,
    }
}

fn location_for_offset(offset: i8, rng: &mut impl Rng) -> SignInLocation {
    let (city, state, country, lat, lon) = match offset {
        -8 => ("Seattle", "WA", "US", 47.6062, -122.3321),
        0 => ("London", "London", "GB", 51.5074, -0.1278),
        8 => ("Singapore", "Singapore", "SG", 1.3521, 103.8198),
        _ => {
            if rng.gen_bool(0.5) {
                ("New York", "NY", "US", 40.7128, -74.0060)
            } else {
                ("Frankfurt", "Hesse", "DE", 50.1109, 8.6821)
            }
        }
    };

    SignInLocation {
        city: city.to_string(),
        state: state.to_string(),
        country_or_region: country.to_string(),
        geo_coordinates: GeoCoordinates {
            altitude: None,
            latitude: lat,
            longitude: lon,
        },
    }
}

fn target_resource_for(
    activity: &str,
    ctx: &EntraActorContext,
    rng: &mut impl Rng,
) -> TargetResource {
    let (resource_type, name_prefix, property) = match activity {
        "AddUser" | "UpdateUser" | "DeleteUser" | "ResetPassword" => {
            ("User", "user", "accountEnabled")
        }
        "AddGroupMember" | "RemoveGroupMember" => ("Group", "group", "members"),
        "AddAppRoleAssignment" => ("ServicePrincipal", "app", "appRoleAssignment"),
        "UpdateConditionalAccess" => ("ConditionalAccessPolicy", "policy", "state"),
        _ => ("DirectoryObject", "object", "displayName"),
    };
    let display_name = format!("{}-{}", name_prefix, rng.gen_range(1000..9999));
    let user_principal_name = if resource_type == "User" {
        Some(format!(
            "{}@{}",
            display_name.replace('-', ""),
            ctx.tenant_domain.to_lowercase()
        ))
    } else {
        None
    };
    let group_type = if resource_type == "Group" {
        Some("Unified".to_string())
    } else {
        None
    };
    let modified_properties = if activity.starts_with("Update") || activity == "ResetPassword" {
        vec![ModifiedProperty {
            display_name: property.to_string(),
            old_value: Some("previous".to_string()),
            new_value: Some("updated".to_string()),
        }]
    } else {
        Vec::new()
    };

    TargetResource {
        id: stable_guid(resource_type, &display_name),
        display_name,
        resource_type: resource_type.to_string(),
        user_principal_name,
        group_type,
        modified_properties,
    }
}

fn conditional_access_policies(
    status: &str,
    rng: &mut impl Rng,
) -> Vec<AppliedConditionalAccessPolicy> {
    if status == "notApplied" {
        return Vec::new();
    }
    let result = if status == "failure" {
        "failure"
    } else if rng.gen_bool(0.2) {
        "notApplied"
    } else {
        "success"
    };
    vec![AppliedConditionalAccessPolicy {
        display_name: "Require MFA".to_string(),
        enforced_grant_controls: vec!["mfa".to_string()],
        enforced_session_controls: Vec::new(),
        id: stable_guid("cap", "mfa"),
        result: result.to_string(),
    }]
}

fn audit_category(activity: &str) -> &'static str {
    match activity {
        "AddUser" | "UpdateUser" | "DeleteUser" | "ResetPassword" => "UserManagement",
        "AddGroupMember" | "RemoveGroupMember" => "GroupManagement",
        "AddAppRoleAssignment" => "AppManagement",
        "UpdateConditionalAccess" => "Policy",
        _ => "Other",
    }
}

fn audit_operation(activity: &str) -> &'static str {
    match activity {
        "AddUser" | "AddGroupMember" | "AddAppRoleAssignment" => "Add",
        "RemoveGroupMember" => "Remove",
        "DeleteUser" => "Delete",
        "ResetPassword" => "Reset",
        "UpdateUser" | "UpdateConditionalAccess" => "Update",
        _ => "Other",
    }
}

fn audit_additional_details(activity: &str) -> Vec<KeyValue> {
    vec![
        KeyValue {
            key: "activity".to_string(),
            value: activity.to_string(),
        },
        KeyValue {
            key: "client".to_string(),
            value: "seclog".to_string(),
        },
    ]
}
