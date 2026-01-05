use crate::model::{CloudTrailEvent, SessionAttributes, SessionContext, TlsDetails, UserIdentity};
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct ActorContext {
    pub identity_type: String,
    pub principal_id: String,
    pub arn: String,
    pub account_id: String,
    pub access_key_id: Option<String>,
    pub user_name: Option<String>,
    pub user_agent: String,
    pub source_ip: String,
    pub region: String,
    pub mfa_authenticated: bool,
    pub session_credential_from_console: bool,
}

#[derive(Debug, Clone)]
pub struct ErrorProfile {
    pub rate: f64,
    pub code: String,
    pub message: String,
}

#[derive(Debug)]
pub enum TemplateError {
    EmptyEventName,
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateError::EmptyEventName => write!(f, "event name must not be empty"),
        }
    }
}

impl std::error::Error for TemplateError {}

pub fn build_cloudtrail_event(
    event_name: &str,
    actor: &ActorContext,
    rng: &mut impl Rng,
    event_time: &str,
    error_profile: Option<ErrorProfile>,
) -> Result<CloudTrailEvent, TemplateError> {
    if event_name.trim().is_empty() {
        return Err(TemplateError::EmptyEventName);
    }

    let base = BaseFields::new(actor, rng, event_time);
    let event = match event_name {
        "ConsoleLogin" => console_login(base),
        "AssumeRole" => assume_role(base, rng),
        "GetSessionToken" => get_session_token(base, rng),
        "PutObject" => s3_put_object(base, rng),
        "GetObject" => s3_get_object(base, rng),
        "RunInstances" => ec2_run_instances(base, rng),
        "StartInstances" => ec2_start_instances(base, rng),
        "StopInstances" => ec2_stop_instances(base, rng),
        _ => generic_event(base, event_name),
    };

    Ok(apply_error(event, rng, error_profile))
}

struct BaseFields {
    event_time: String,
    aws_region: String,
    source_ip_address: String,
    user_agent: String,
    account_id: String,
    user_identity: UserIdentity,
    request_id: String,
    event_id: String,
    session_credential_from_console: bool,
}

impl BaseFields {
    fn new(actor: &ActorContext, rng: &mut impl Rng, event_time: &str) -> Self {
        let account_id = actor.account_id.clone();
        let user_name = actor.user_name.clone();
        let session_context = session_context_for(actor, event_time);
        let user_identity = UserIdentity {
            identity_type: actor.identity_type.clone(),
            principal_id: actor.principal_id.clone(),
            arn: actor.arn.clone(),
            account_id: account_id.clone(),
            access_key_id: actor.access_key_id.clone(),
            user_name,
            session_context,
        };

        Self {
            event_time: event_time.to_string(),
            aws_region: actor.region.clone(),
            source_ip_address: actor.source_ip.clone(),
            user_agent: actor.user_agent.clone(),
            account_id,
            user_identity,
            request_id: random_request_id(rng),
            event_id: random_event_id(rng),
            session_credential_from_console: actor.session_credential_from_console,
        }
    }
}

fn console_login(base: BaseFields) -> CloudTrailEvent {
    let mut event = base_event(base, "signin.amazonaws.com", "ConsoleLogin", Some(true));
    event.request_parameters = Some(json!({
        "loginTo": "https://console.aws.amazon.com",
        "mfaUsed": if event
            .user_identity
            .session_context
            .as_ref()
            .map(|ctx| ctx.attributes.mfa_authenticated.as_str())
            .unwrap_or("false") == "true" { "Yes" } else { "No" },
    }));
    event.response_elements = Some(json!({
        "ConsoleLogin": "Success",
    }));
    event.event_type = Some("AwsConsoleSignIn".to_string());
    event
}

fn assume_role(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    let role_name = format!("demo-role-{}", random_alpha(rng, 4));
    let role_arn = format!("arn:aws:iam::{}:role/{}", base.account_id, role_name);
    let mut event = base_event(base, "sts.amazonaws.com", "AssumeRole", Some(false));
    event.request_parameters = Some(json!({
        "roleArn": role_arn,
        "roleSessionName": format!("session-{}", random_alpha(rng, 8)),
    }));
    event.response_elements = Some(json!({
        "credentials": {
            "accessKeyId": format!("example-key-{}", random_alpha(rng, 12).to_lowercase()),
            "expiration": "2024-01-01T00:00:00Z",
        }
    }));
    event
}

fn get_session_token(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    let mut event = base_event(base, "sts.amazonaws.com", "GetSessionToken", Some(false));
    event.request_parameters = Some(json!({
        "durationSeconds": 3600,
        "serialNumber": format!("arn:aws:iam::{}:mfa/user", random_account_id(rng)),
        "tokenCode": format!("{}", rng.gen_range(100000..999999)),
    }));
    event.response_elements = Some(json!({
        "credentials": {
            "accessKeyId": format!("example-key-{}", random_alpha(rng, 12).to_lowercase()),
            "expiration": "2024-01-01T01:00:00Z",
        }
    }));
    event
}

fn s3_put_object(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    let bucket = random_bucket_name(rng);
    let key = format!("logs/{}/{}.json", random_alpha(rng, 4), random_alpha(rng, 10));
    let mut event = base_event(base, "s3.amazonaws.com", "PutObject", Some(false));
    event.request_parameters = Some(json!({
        "bucketName": bucket,
        "key": key,
    }));
    event.response_elements = Some(json!({
        "x-amz-request-id": random_alpha(rng, 16),
    }));
    event
}

fn s3_get_object(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    let bucket = random_bucket_name(rng);
    let key = format!("data/{}/{}.parquet", random_alpha(rng, 4), random_alpha(rng, 10));
    let mut event = base_event(base, "s3.amazonaws.com", "GetObject", Some(true));
    event.request_parameters = Some(json!({
        "bucketName": bucket,
        "key": key,
    }));
    event
}

fn ec2_run_instances(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    let instance_id = format!("i-{}", random_alpha(rng, 16));
    let mut event = base_event(base, "ec2.amazonaws.com", "RunInstances", Some(false));
    event.request_parameters = Some(json!({
        "instanceType": "t3.medium",
        "minCount": 1,
        "maxCount": 1,
    }));
    event.response_elements = Some(json!({
        "instancesSet": [{
            "instanceId": instance_id,
            "state": {"name": "pending"},
        }]
    }));
    event
}

fn ec2_start_instances(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    let instances = random_instance_set(rng);
    let mut event = base_event(base, "ec2.amazonaws.com", "StartInstances", Some(false));
    event.request_parameters = Some(json!({
        "instancesSet": { "items": instances.iter().map(|id| json!({ "instanceId": id })).collect::<Vec<_>>() }
    }));
    event.response_elements = Some(json!({
        "instancesSet": {
            "items": instances.iter().map(|id| json!({
                "instanceId": id,
                "currentState": { "code": 0, "name": "pending" },
                "previousState": { "code": 80, "name": "stopped" }
            })).collect::<Vec<_>>()
        }
    }));
    event
}

fn ec2_stop_instances(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    let instances = random_instance_set(rng);
    let mut event = base_event(base, "ec2.amazonaws.com", "StopInstances", Some(false));
    event.request_parameters = Some(json!({
        "instancesSet": { "items": instances.iter().map(|id| json!({ "instanceId": id })).collect::<Vec<_>>() },
        "force": false,
    }));
    event.response_elements = Some(json!({
        "instancesSet": {
            "items": instances.iter().map(|id| json!({
                "instanceId": id,
                "currentState": { "code": 64, "name": "stopping" },
                "previousState": { "code": 16, "name": "running" }
            })).collect::<Vec<_>>()
        }
    }));
    event
}

fn generic_event(base: BaseFields, event_name: &str) -> CloudTrailEvent {
    let event_source = event_source_for(event_name);
    let mut event = base_event(base, event_source, event_name, read_only_for(event_name));
    event.request_parameters = Some(Value::Object(Default::default()));
    event
}

fn base_event(
    base: BaseFields,
    event_source: &str,
    event_name: &str,
    read_only: Option<bool>,
) -> CloudTrailEvent {
    CloudTrailEvent {
        event_version: "1.08".to_string(),
        event_time: base.event_time,
        event_source: event_source.to_string(),
        event_name: event_name.to_string(),
        aws_region: base.aws_region,
        source_ip_address: base.source_ip_address,
        user_agent: base.user_agent,
        user_identity: base.user_identity,
        request_parameters: None,
        response_elements: None,
        request_id: base.request_id,
        event_id: base.event_id,
        read_only,
        event_type: Some(event_type_for(event_name).to_string()),
        management_event: Some(true),
        recipient_account_id: base.account_id,
        event_category: Some("Management".to_string()),
        tls_details: Some(tls_details_for(event_source)),
        session_credential_from_console: Some(base.session_credential_from_console),
        error_code: None,
        error_message: None,
    }
}

fn random_event_id(rng: &mut impl Rng) -> String {
    random_uuid(rng)
}

fn random_request_id(rng: &mut impl Rng) -> String {
    random_uuid(rng)
}

fn random_account_id(rng: &mut impl Rng) -> String {
    (0..12).map(|_| rng.gen_range(0..10).to_string()).collect()
}

fn random_bucket_name(rng: &mut impl Rng) -> String {
    format!("demo-bucket-{}", random_alpha(rng, 6).to_lowercase())
}

fn random_alpha(rng: &mut impl Rng, len: usize) -> String {
    rng.sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn random_uuid(rng: &mut impl Rng) -> String {
    let mut out = String::with_capacity(36);
    let sections = [8, 4, 4, 4, 12];
    for (idx, count) in sections.iter().enumerate() {
        if idx > 0 {
            out.push('-');
        }
        for _ in 0..*count {
            let v: u8 = rng.gen_range(0..16);
            out.push(std::char::from_digit(v as u32, 16).unwrap());
        }
    }
    out
}

fn event_type_for(event_name: &str) -> &'static str {
    match event_name {
        "ConsoleLogin" => "AwsConsoleSignIn",
        _ => "AwsApiCall",
    }
}

fn read_only_for(event_name: &str) -> Option<bool> {
    match event_name {
        "GetObject"
        | "DescribeInstances"
        | "GetCallerIdentity"
        | "DescribeLogStreams"
        | "GetMetricData"
        | "ListMetrics" => Some(true),
        "ConsoleLogin" => Some(true),
        _ => Some(false),
    }
}

fn event_source_for(event_name: &str) -> &'static str {
    match event_name {
        "ConsoleLogin" => "signin.amazonaws.com",
        "AssumeRole" | "GetSessionToken" | "GetCallerIdentity" => "sts.amazonaws.com",
        "PutObject" | "GetObject" | "DeleteObject" | "CreateBucket" | "DeleteBucket" => {
            "s3.amazonaws.com"
        }
        "RunInstances"
        | "StartInstances"
        | "StopInstances"
        | "TerminateInstances"
        | "DescribeInstances"
        | "CreateSecurityGroup"
        | "AuthorizeSecurityGroupIngress" => "ec2.amazonaws.com",
        "CreateUser"
        | "DeleteUser"
        | "CreateAccessKey"
        | "UpdateAccessKey"
        | "AttachRolePolicy"
        | "AddUserToGroup"
        | "CreateRole" => "iam.amazonaws.com",
        "CreateLogGroup" | "CreateLogStream" | "DescribeLogStreams" | "PutLogEvents" => {
            "logs.amazonaws.com"
        }
        "Encrypt" | "Decrypt" | "GenerateDataKey" => "kms.amazonaws.com",
        "PutMetricData" | "GetMetricData" | "ListMetrics" => "monitoring.amazonaws.com",
        "UpdateTrail" => "cloudtrail.amazonaws.com",
        _ => "unknown.amazonaws.com",
    }
}

fn tls_details_for(event_source: &str) -> TlsDetails {
    TlsDetails {
        tls_version: "TLSv1.2".to_string(),
        cipher_suite: "ECDHE-RSA-AES128-GCM-SHA256".to_string(),
        client_provided_host_header: event_source.to_string(),
    }
}

fn session_context_for(actor: &ActorContext, event_time: &str) -> Option<SessionContext> {
    Some(SessionContext {
        session_issuer: json!({}),
        web_id_federation_data: json!({}),
        attributes: SessionAttributes {
            creation_date: event_time.to_string(),
            mfa_authenticated: if actor.mfa_authenticated {
                "true".to_string()
            } else {
                "false".to_string()
            },
        },
    })
}

fn random_instance_set(rng: &mut impl Rng) -> Vec<String> {
    let count = rng.gen_range(1..=2);
    (0..count)
        .map(|_| format!("i-{}", random_alpha(rng, 16).to_lowercase()))
        .collect()
}

pub fn apply_error(
    mut event: CloudTrailEvent,
    rng: &mut impl Rng,
    profile: Option<ErrorProfile>,
) -> CloudTrailEvent {
    let profile = match profile {
        Some(profile) => profile,
        None => return event,
    };

    if rng.gen_bool(profile.rate) {
        event.error_code = Some(profile.code);
        event.error_message = Some(profile.message);
        if event.event_name == "ConsoleLogin" {
            event.response_elements = Some(json!({
                "ConsoleLogin": "Failure",
            }));
        } else {
            event.response_elements = None;
        }
    }

    event
}

pub fn default_error_profile(event_name: &str) -> Option<ErrorProfile> {
    let profile = match event_name {
        "ConsoleLogin" => ErrorProfile {
            rate: 0.08,
            code: "SigninFailure".to_string(),
            message: "Failed authentication".to_string(),
        },
        "GetSessionToken" => ErrorProfile {
            rate: 0.05,
            code: "AccessDenied".to_string(),
            message: "Invalid MFA token".to_string(),
        },
        "AssumeRole" => ErrorProfile {
            rate: 0.03,
            code: "AccessDenied".to_string(),
            message: "Not authorized to assume role".to_string(),
        },
        "PutObject" | "GetObject" => ErrorProfile {
            rate: 0.02,
            code: "AccessDenied".to_string(),
            message: "Access denied".to_string(),
        },
        "RunInstances" => ErrorProfile {
            rate: 0.02,
            code: "UnauthorizedOperation".to_string(),
            message: "Not authorized to perform operation".to_string(),
        },
        _ => ErrorProfile {
            rate: 0.01,
            code: "AccessDenied".to_string(),
            message: "Access denied".to_string(),
        },
    };
    Some(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn console_login_template() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let actor = ActorContext {
            identity_type: "IAMUser".to_string(),
            principal_id: "AIDA_TEST_001".to_string(),
            arn: "arn:aws:iam::123456789012:user/test".to_string(),
            account_id: "123456789012".to_string(),
            access_key_id: Some("AKIATEST1234567890".to_string()),
            user_name: Some("test".to_string()),
            user_agent: "aws-cli/2.15.0".to_string(),
            source_ip: "10.0.0.1".to_string(),
            region: "us-east-1".to_string(),
            mfa_authenticated: true,
            session_credential_from_console: false,
        };
        let event = build_cloudtrail_event(
            "ConsoleLogin",
            &actor,
            &mut rng,
            "2024-01-01T00:00:00Z",
            None,
        )
            .expect("event");
        assert_eq!(event.event_source, "signin.amazonaws.com");
        assert_eq!(event.event_name, "ConsoleLogin");
        assert!(event.request_parameters.is_some());
    }
}
