use crate::model::{CloudTrailEvent, UserIdentity};
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct ActorContext {
    pub identity_type: String,
    pub principal_id: String,
    pub arn: String,
    pub account_id: String,
    pub user_name: Option<String>,
    pub user_agent: String,
    pub source_ip: String,
    pub region: String,
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

    let base = BaseFields::new(actor, event_time);
    let event = match event_name {
        "ConsoleLogin" => console_login(base, rng),
        "AssumeRole" => assume_role(base, rng),
        "GetSessionToken" => get_session_token(base, rng),
        "PutObject" => s3_put_object(base, rng),
        "GetObject" => s3_get_object(base, rng),
        "RunInstances" => ec2_run_instances(base, rng),
        _ => generic_event(base, rng, event_name),
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
}

impl BaseFields {
    fn new(actor: &ActorContext, event_time: &str) -> Self {
        let account_id = actor.account_id.clone();
        let user_name = actor.user_name.clone();
        let user_identity = UserIdentity {
            identity_type: actor.identity_type.clone(),
            principal_id: actor.principal_id.clone(),
            arn: actor.arn.clone(),
            account_id: account_id.clone(),
            user_name,
        };

        Self {
            event_time: event_time.to_string(),
            aws_region: actor.region.clone(),
            source_ip_address: actor.source_ip.clone(),
            user_agent: actor.user_agent.clone(),
            account_id,
            user_identity,
        }
    }
}

fn console_login(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    CloudTrailEvent {
        event_version: "1.08".to_string(),
        event_time: base.event_time,
        event_source: "signin.amazonaws.com".to_string(),
        event_name: "ConsoleLogin".to_string(),
        aws_region: base.aws_region,
        source_ip_address: base.source_ip_address,
        user_agent: base.user_agent,
        user_identity: base.user_identity,
        request_parameters: Some(json!({
            "LoginTo": "https://console.aws.amazon.com",
            "MFAUsed": "Yes",
        })),
        response_elements: Some(json!({
            "ConsoleLogin": "Success",
        })),
        error_code: None,
        error_message: None,
        event_id: random_event_id(rng),
        recipient_account_id: base.account_id,
        read_only: Some(true),
    }
}

fn assume_role(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    let role_name = format!("demo-role-{}", random_alpha(rng, 4));
    let role_arn = format!("arn:aws:iam::{}:role/{}", base.account_id, role_name);
    CloudTrailEvent {
        event_version: "1.08".to_string(),
        event_time: base.event_time,
        event_source: "sts.amazonaws.com".to_string(),
        event_name: "AssumeRole".to_string(),
        aws_region: base.aws_region,
        source_ip_address: base.source_ip_address,
        user_agent: base.user_agent,
        user_identity: base.user_identity,
        request_parameters: Some(json!({
            "roleArn": role_arn,
            "roleSessionName": format!("session-{}", random_alpha(rng, 8)),
        })),
        response_elements: Some(json!({
            "credentials": {
                "accessKeyId": format!("example-key-{}", random_alpha(rng, 12).to_lowercase()),
                "expiration": "2024-01-01T00:00:00Z",
            }
        })),
        error_code: None,
        error_message: None,
        event_id: random_event_id(rng),
        recipient_account_id: base.account_id,
        read_only: Some(false),
    }
}

fn get_session_token(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    CloudTrailEvent {
        event_version: "1.08".to_string(),
        event_time: base.event_time,
        event_source: "sts.amazonaws.com".to_string(),
        event_name: "GetSessionToken".to_string(),
        aws_region: base.aws_region,
        source_ip_address: base.source_ip_address,
        user_agent: base.user_agent,
        user_identity: base.user_identity,
        request_parameters: Some(json!({
            "durationSeconds": 3600,
            "serialNumber": format!("arn:aws:iam::{}:mfa/user", random_account_id(rng)),
            "tokenCode": format!("{}", rng.gen_range(100000..999999)),
        })),
        response_elements: Some(json!({
            "credentials": {
                "accessKeyId": format!("example-key-{}", random_alpha(rng, 12).to_lowercase()),
                "expiration": "2024-01-01T01:00:00Z",
            }
        })),
        error_code: None,
        error_message: None,
        event_id: random_event_id(rng),
        recipient_account_id: base.account_id,
        read_only: Some(false),
    }
}

fn s3_put_object(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    let bucket = random_bucket_name(rng);
    let key = format!("logs/{}/{}.json", random_alpha(rng, 4), random_alpha(rng, 10));
    CloudTrailEvent {
        event_version: "1.08".to_string(),
        event_time: base.event_time,
        event_source: "s3.amazonaws.com".to_string(),
        event_name: "PutObject".to_string(),
        aws_region: base.aws_region,
        source_ip_address: base.source_ip_address,
        user_agent: base.user_agent,
        user_identity: base.user_identity,
        request_parameters: Some(json!({
            "bucketName": bucket,
            "key": key,
        })),
        response_elements: Some(json!({
            "x-amz-request-id": random_alpha(rng, 16),
        })),
        error_code: None,
        error_message: None,
        event_id: random_event_id(rng),
        recipient_account_id: base.account_id,
        read_only: Some(false),
    }
}

fn s3_get_object(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    let bucket = random_bucket_name(rng);
    let key = format!("data/{}/{}.parquet", random_alpha(rng, 4), random_alpha(rng, 10));
    CloudTrailEvent {
        event_version: "1.08".to_string(),
        event_time: base.event_time,
        event_source: "s3.amazonaws.com".to_string(),
        event_name: "GetObject".to_string(),
        aws_region: base.aws_region,
        source_ip_address: base.source_ip_address,
        user_agent: base.user_agent,
        user_identity: base.user_identity,
        request_parameters: Some(json!({
            "bucketName": bucket,
            "key": key,
        })),
        response_elements: None,
        error_code: None,
        error_message: None,
        event_id: random_event_id(rng),
        recipient_account_id: base.account_id,
        read_only: Some(true),
    }
}

fn ec2_run_instances(base: BaseFields, rng: &mut impl Rng) -> CloudTrailEvent {
    let instance_id = format!("i-{}", random_alpha(rng, 16));
    CloudTrailEvent {
        event_version: "1.08".to_string(),
        event_time: base.event_time,
        event_source: "ec2.amazonaws.com".to_string(),
        event_name: "RunInstances".to_string(),
        aws_region: base.aws_region,
        source_ip_address: base.source_ip_address,
        user_agent: base.user_agent,
        user_identity: base.user_identity,
        request_parameters: Some(json!({
            "instanceType": "t3.medium",
            "minCount": 1,
            "maxCount": 1,
        })),
        response_elements: Some(json!({
            "instancesSet": [{
                "instanceId": instance_id,
                "state": {"name": "pending"},
            }]
        })),
        error_code: None,
        error_message: None,
        event_id: random_event_id(rng),
        recipient_account_id: base.account_id,
        read_only: Some(false),
    }
}

fn generic_event(base: BaseFields, rng: &mut impl Rng, event_name: &str) -> CloudTrailEvent {
    CloudTrailEvent {
        event_version: "1.08".to_string(),
        event_time: base.event_time,
        event_source: "unknown.amazonaws.com".to_string(),
        event_name: event_name.to_string(),
        aws_region: base.aws_region,
        source_ip_address: base.source_ip_address,
        user_agent: base.user_agent,
        user_identity: base.user_identity,
        request_parameters: Some(Value::Object(Default::default())),
        response_elements: None,
        error_code: None,
        error_message: None,
        event_id: random_event_id(rng),
        recipient_account_id: base.account_id,
        read_only: None,
    }
}

fn random_event_id(rng: &mut impl Rng) -> String {
    random_alpha(rng, 24)
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
            user_name: Some("test".to_string()),
            user_agent: "aws-cli/2.15.0".to_string(),
            source_ip: "10.0.0.1".to_string(),
            region: "us-east-1".to_string(),
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
