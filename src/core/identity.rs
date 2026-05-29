//! Shared identity registry support for cross-source generators.
//!
//! The registry is intentionally data-driven. Scenario-specific people,
//! service accounts, and platform identifiers should live in registry files,
//! while generators consume the normalized identities through this module.

use super::actors::{ActorKind, ActorPopulation, ActorRole, ActorSeed, ServiceProfile};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Error while loading or validating an identity registry.
#[derive(Debug)]
pub enum IdentityRegistryError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    DuplicateKey {
        field: &'static str,
        value: String,
    },
    EmptyIdentityField {
        actor_id: String,
        field: &'static str,
    },
}

impl std::fmt::Display for IdentityRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityRegistryError::Io(err) => write!(f, "identity registry io error: {err}"),
            IdentityRegistryError::Parse(err) => write!(f, "identity registry parse error: {err}"),
            IdentityRegistryError::DuplicateKey { field, value } => {
                write!(f, "identity registry has duplicate {field}: {value}")
            }
            IdentityRegistryError::EmptyIdentityField { actor_id, field } => {
                write!(f, "identity {actor_id} has empty {field}")
            }
        }
    }
}

impl std::error::Error for IdentityRegistryError {}

impl From<std::io::Error> for IdentityRegistryError {
    fn from(err: std::io::Error) -> Self {
        IdentityRegistryError::Io(err)
    }
}

impl From<toml::de::Error> for IdentityRegistryError {
    fn from(err: toml::de::Error) -> Self {
        IdentityRegistryError::Parse(err)
    }
}

/// Cross-system AWS identifiers for an actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsPrincipal {
    pub account_id: String,
    pub principal_id: String,
    pub arn: String,
    pub role_name: Option<String>,
    pub role_session_name: Option<String>,
    pub access_key_id: Option<String>,
}

/// Stable identity shared by source generators.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    pub actor_id: String,
    pub email: String,
    pub employee_id: String,
    pub display_name: String,
    pub role_persona: String,
    pub department: String,
    pub home_location: String,
    #[serde(default)]
    pub normal_countries_regions: Vec<String>,
    pub okta_user_id: String,
    pub databricks_username: String,
    #[serde(default)]
    pub aws_principals: Vec<AwsPrincipal>,
    #[serde(default)]
    pub service_account: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub rate_per_hour: Option<f64>,
}

/// Registry file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRegistryFile {
    pub name: Option<String>,
    #[serde(rename = "identity")]
    pub identities: Vec<Identity>,
}

/// Identity registry with convenience lookup indexes.
#[derive(Debug, Clone)]
pub struct IdentityRegistry {
    name: String,
    identities: Vec<Identity>,
    by_actor_id: HashMap<String, usize>,
    by_email: HashMap<String, usize>,
    by_okta_user_id: HashMap<String, usize>,
    by_databricks_username: HashMap<String, usize>,
    by_aws_principal_id: HashMap<String, usize>,
    by_aws_arn: HashMap<String, usize>,
}

impl IdentityRegistry {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, IdentityRegistryError> {
        let contents = fs::read_to_string(path)?;
        let file: IdentityRegistryFile = toml::from_str(&contents)?;
        Self::from_file(file)
    }

    pub fn from_file(file: IdentityRegistryFile) -> Result<Self, IdentityRegistryError> {
        Self::new(
            file.name.unwrap_or_else(|| "identity_registry".to_string()),
            file.identities,
        )
    }

    pub fn new(
        name: impl Into<String>,
        identities: Vec<Identity>,
    ) -> Result<Self, IdentityRegistryError> {
        let mut registry = Self {
            name: name.into(),
            identities,
            by_actor_id: HashMap::new(),
            by_email: HashMap::new(),
            by_okta_user_id: HashMap::new(),
            by_databricks_username: HashMap::new(),
            by_aws_principal_id: HashMap::new(),
            by_aws_arn: HashMap::new(),
        };
        registry.rebuild_indexes()?;
        Ok(registry)
    }

    pub fn from_population(
        name: impl Into<String>,
        population: &ActorPopulation,
    ) -> Result<Self, IdentityRegistryError> {
        let mut human_index = 0_usize;
        let mut service_index = 0_usize;
        let identities = population
            .actors
            .iter()
            .enumerate()
            .map(|(idx, actor)| {
                let ordinal = match actor.kind {
                    ActorKind::Human => {
                        human_index += 1;
                        human_index
                    }
                    ActorKind::Service => {
                        service_index += 1;
                        service_index
                    }
                };
                identity_from_actor_seed(actor, idx, ordinal)
            })
            .collect();
        Self::new(name, identities)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn identities(&self) -> &[Identity] {
        &self.identities
    }

    pub fn get(&self, actor_id: &str) -> Option<&Identity> {
        self.by_actor_id
            .get(actor_id)
            .and_then(|idx| self.identities.get(*idx))
    }

    pub fn resolve_email(&self, email: &str) -> Option<&Identity> {
        self.by_email
            .get(&normalize_key(email))
            .and_then(|idx| self.identities.get(*idx))
    }

    pub fn resolve_okta_user_id(&self, okta_user_id: &str) -> Option<&Identity> {
        self.by_okta_user_id
            .get(okta_user_id)
            .and_then(|idx| self.identities.get(*idx))
    }

    pub fn resolve_databricks_username(&self, username: &str) -> Option<&Identity> {
        self.by_databricks_username
            .get(&normalize_key(username))
            .and_then(|idx| self.identities.get(*idx))
    }

    pub fn resolve_aws_principal_id(&self, principal_id: &str) -> Option<&Identity> {
        self.by_aws_principal_id
            .get(principal_id)
            .and_then(|idx| self.identities.get(*idx))
    }

    pub fn resolve_aws_arn(&self, arn: &str) -> Option<&Identity> {
        self.by_aws_arn
            .get(arn)
            .and_then(|idx| self.identities.get(*idx))
    }

    fn rebuild_indexes(&mut self) -> Result<(), IdentityRegistryError> {
        for idx in 0..self.identities.len() {
            self.validate_identity(idx)?;
            let identity = &self.identities[idx];
            insert_unique(
                &mut self.by_actor_id,
                "actor_id",
                identity.actor_id.clone(),
                idx,
            )?;
            insert_unique(
                &mut self.by_email,
                "email",
                normalize_key(&identity.email),
                idx,
            )?;
            insert_unique(
                &mut self.by_okta_user_id,
                "okta_user_id",
                identity.okta_user_id.clone(),
                idx,
            )?;
            insert_unique(
                &mut self.by_databricks_username,
                "databricks_username",
                normalize_key(&identity.databricks_username),
                idx,
            )?;
            for principal in &identity.aws_principals {
                insert_unique(
                    &mut self.by_aws_principal_id,
                    "aws_principal_id",
                    principal.principal_id.clone(),
                    idx,
                )?;
                insert_unique(&mut self.by_aws_arn, "aws_arn", principal.arn.clone(), idx)?;
            }
        }
        Ok(())
    }

    fn validate_identity(&self, idx: usize) -> Result<(), IdentityRegistryError> {
        let identity = &self.identities[idx];
        require_non_empty(&identity.actor_id, &identity.actor_id, "actor_id")?;
        require_non_empty(&identity.actor_id, &identity.email, "email")?;
        require_non_empty(&identity.actor_id, &identity.employee_id, "employee_id")?;
        require_non_empty(&identity.actor_id, &identity.display_name, "display_name")?;
        require_non_empty(&identity.actor_id, &identity.role_persona, "role_persona")?;
        require_non_empty(&identity.actor_id, &identity.department, "department")?;
        require_non_empty(&identity.actor_id, &identity.home_location, "home_location")?;
        require_non_empty(&identity.actor_id, &identity.okta_user_id, "okta_user_id")?;
        require_non_empty(
            &identity.actor_id,
            &identity.databricks_username,
            "databricks_username",
        )?;
        for principal in &identity.aws_principals {
            require_non_empty(&identity.actor_id, &principal.account_id, "aws.account_id")?;
            require_non_empty(
                &identity.actor_id,
                &principal.principal_id,
                "aws.principal_id",
            )?;
            require_non_empty(&identity.actor_id, &principal.arn, "aws.arn")?;
        }
        Ok(())
    }
}

fn identity_from_actor_seed(actor: &ActorSeed, idx: usize, ordinal: usize) -> Identity {
    let service_account = matches!(actor.kind, ActorKind::Service);
    let actor_id = actor.id.clone().unwrap_or_else(|| {
        if service_account {
            format!("svc-{ordinal:04}")
        } else {
            format!("human-{ordinal:04}")
        }
    });
    let user_name = actor
        .user_name
        .as_deref()
        .and_then(non_empty)
        .map(str::to_string)
        .unwrap_or_else(|| username_from_actor(actor, &actor_id, ordinal));
    let display_name = actor
        .display_name
        .as_deref()
        .and_then(non_empty)
        .map(str::to_string)
        .unwrap_or_else(|| display_name_from_actor(actor, &user_name, ordinal));
    let email = actor
        .email
        .as_deref()
        .and_then(non_empty)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if service_account {
                format!(
                    "{}.{ordinal:04}@example.internal",
                    service_email_local_part(&display_name, ordinal)
                )
            } else {
                format!("{user_name}@example.com")
            }
        });
    let normal_countries_regions = if actor.normal_countries_regions.is_empty() {
        actor
            .home_location
            .as_deref()
            .and_then(non_empty)
            .map(|location| vec![location.to_string()])
            .unwrap_or_default()
    } else {
        actor.normal_countries_regions.clone()
    };
    let home_location = actor
        .home_location
        .as_deref()
        .and_then(non_empty)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if service_account {
                "Cloud service account".to_string()
            } else {
                "Unassigned location".to_string()
            }
        });
    let employee_id = if service_account {
        format!("SVC-{:06}", 100000 + ordinal)
    } else {
        format!("E-{:06}", 100000 + ordinal)
    };
    let okta_user_id = if service_account {
        format!("0oa{}", stable_token(&actor_id, idx, 17))
    } else {
        format!("00u{}", stable_token(&actor_id, idx, 17))
    };
    let databricks_username = email.clone();

    Identity {
        actor_id: actor_id.clone(),
        email,
        employee_id,
        display_name,
        role_persona: role_persona(actor),
        department: department(actor),
        home_location,
        normal_countries_regions,
        okta_user_id,
        databricks_username,
        aws_principals: vec![aws_principal_from_actor(actor)],
        service_account,
        tags: actor.tags.clone(),
        rate_per_hour: Some(actor.rate_per_hour),
    }
}

fn aws_principal_from_actor(actor: &ActorSeed) -> AwsPrincipal {
    let (role_name, role_session_name) = assumed_role_parts(&actor.arn);
    AwsPrincipal {
        account_id: actor.account_id.clone(),
        principal_id: actor.principal_id.clone(),
        arn: actor.arn.clone(),
        role_name,
        role_session_name,
        access_key_id: Some(actor.access_key_id.clone()),
    }
}

fn assumed_role_parts(arn: &str) -> (Option<String>, Option<String>) {
    let Some((_, tail)) = arn.split_once(":assumed-role/") else {
        return (None, None);
    };
    let mut parts = tail.split('/');
    let role_name = parts.next().and_then(non_empty).map(str::to_string);
    let role_session_name = parts.next().and_then(non_empty).map(str::to_string);
    (role_name, role_session_name)
}

fn username_from_actor(actor: &ActorSeed, actor_id: &str, ordinal: usize) -> String {
    if let Some(email) = actor.email.as_deref().and_then(non_empty) {
        if let Some((local, _)) = email.split_once('@') {
            let slug = slug(local);
            if !slug.is_empty() {
                return slug;
            }
        }
    }
    if let Some(display_name) = actor.display_name.as_deref().and_then(non_empty) {
        let slug = slug(display_name);
        if !slug.is_empty() {
            return slug;
        }
    }
    let slug = slug(actor_id);
    if slug.is_empty() {
        format!("actor{ordinal:04}")
    } else {
        slug
    }
}

fn display_name_from_actor(actor: &ActorSeed, user_name: &str, ordinal: usize) -> String {
    if matches!(actor.kind, ActorKind::Service) {
        return actor
            .service_profile
            .as_ref()
            .map(service_display_name)
            .unwrap_or("Automation Service")
            .to_string();
    }
    let parts: Vec<String> = user_name
        .split(|ch: char| ch == '.' || ch == '_' || ch == '-' || ch.is_ascii_digit())
        .filter_map(non_empty)
        .map(title_ascii)
        .collect();
    if parts.len() >= 2 {
        parts.join(" ")
    } else {
        format!("Generated User {ordinal:04}")
    }
}

fn role_persona(actor: &ActorSeed) -> String {
    match actor.kind {
        ActorKind::Human => match actor.role.as_ref().unwrap_or(&ActorRole::Developer) {
            ActorRole::Admin => "Cloud platform administrator",
            ActorRole::Developer => "Data engineering developer",
            ActorRole::ReadOnly => "Business analytics viewer",
            ActorRole::Auditor => "Security and compliance auditor",
        },
        ActorKind::Service => match actor
            .service_profile
            .as_ref()
            .unwrap_or(&ServiceProfile::Generic)
        {
            ServiceProfile::Generic => "Automation service account",
            ServiceProfile::Ec2Reaper => "Compute lifecycle service account",
            ServiceProfile::DataLakeBot => "Data lake automation service account",
            ServiceProfile::LogsShipper => "Log shipping service account",
            ServiceProfile::MetricsCollector => "Metrics collection service account",
        },
    }
    .to_string()
}

fn department(actor: &ActorSeed) -> String {
    match actor.kind {
        ActorKind::Human => match actor.role.as_ref().unwrap_or(&ActorRole::Developer) {
            ActorRole::Admin => "Platform Engineering",
            ActorRole::Developer => "Data Engineering",
            ActorRole::ReadOnly => "Business Operations",
            ActorRole::Auditor => "Security",
        },
        ActorKind::Service => "Platform Engineering",
    }
    .to_string()
}

fn service_display_name(profile: &ServiceProfile) -> &'static str {
    match profile {
        ServiceProfile::Generic => "Automation Service",
        ServiceProfile::Ec2Reaper => "EC2 Reaper Service",
        ServiceProfile::DataLakeBot => "Data Lake Bot Service",
        ServiceProfile::LogsShipper => "Logs Shipper Service",
        ServiceProfile::MetricsCollector => "Metrics Collector Service",
    }
}

fn service_email_local_part(display_name: &str, ordinal: usize) -> String {
    let slug = slug(display_name);
    if slug.is_empty() {
        format!("svc{ordinal:04}")
    } else if slug.starts_with("svc.") {
        slug
    } else {
        format!("svc.{slug}")
    }
}

fn slug(value: &str) -> String {
    let mut out = String::new();
    let mut previous_dot = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            previous_dot = false;
        } else if !previous_dot {
            out.push('.');
            previous_dot = true;
        }
    }
    out.trim_matches('.').to_string()
}

fn title_ascii(value: &str) -> String {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut result = String::new();
    result.push(first.to_ascii_uppercase());
    result.push_str(chars.as_str().to_ascii_lowercase().as_str());
    result
}

fn stable_token(actor_id: &str, idx: usize, len: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut hash = stable_hash(&format!("{actor_id}:{idx}"));
    let mut token = String::with_capacity(len);
    for _ in 0..len {
        let alphabet_idx = (hash % ALPHABET.len() as u64) as usize;
        token.push(ALPHABET[alphabet_idx] as char);
        hash = hash.rotate_left(7).wrapping_mul(0x9E3779B185EBCA87);
    }
    token
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn non_empty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn insert_unique(
    index: &mut HashMap<String, usize>,
    field: &'static str,
    value: String,
    idx: usize,
) -> Result<(), IdentityRegistryError> {
    if let Some(existing) = index.insert(value.clone(), idx) {
        index.insert(value.clone(), existing);
        return Err(IdentityRegistryError::DuplicateKey { field, value });
    }
    Ok(())
}

fn require_non_empty(
    actor_id: &str,
    value: &str,
    field: &'static str,
) -> Result<(), IdentityRegistryError> {
    if value.trim().is_empty() {
        return Err(IdentityRegistryError::EmptyIdentityField {
            actor_id: actor_id.to_string(),
            field,
        });
    }
    Ok(())
}

fn normalize_key(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::actors::generate_population;
    use crate::core::config::{PopulationActorsConfig, PopulationConfig, TimezoneWeight};

    #[test]
    fn registry_resolves_cross_system_identity_keys() {
        let registry = test_registry();
        let user = registry.get("user-001").unwrap();

        assert_eq!(
            registry.resolve_email(&user.email).unwrap().actor_id,
            user.actor_id
        );
        assert_eq!(
            registry
                .resolve_databricks_username(&user.databricks_username)
                .unwrap()
                .actor_id,
            user.actor_id
        );
        assert_eq!(
            registry
                .resolve_okta_user_id(&user.okta_user_id)
                .unwrap()
                .actor_id,
            user.actor_id
        );
        let aws = &user.aws_principals[0];
        assert_eq!(
            registry
                .resolve_aws_principal_id(&aws.principal_id)
                .unwrap()
                .actor_id,
            user.actor_id
        );
        assert_eq!(
            registry.resolve_aws_arn(&aws.arn).unwrap().actor_id,
            user.actor_id
        );
    }

    #[test]
    fn registry_rejects_duplicate_email_keys() {
        let mut identities = vec![identity("user-001", "user@example.com")];
        identities.push(identity("user-002", "USER@example.com"));
        let err = IdentityRegistry::new("test", identities).unwrap_err();
        assert!(matches!(
            err,
            IdentityRegistryError::DuplicateKey { field: "email", .. }
        ));
    }

    #[test]
    fn registry_can_be_synthesized_from_actor_population() {
        let population = generate_population(&PopulationConfig {
            seed: Some(17),
            timezone_distribution: Some(vec![TimezoneWeight {
                name: "Asia/Singapore".to_string(),
                weight: 1.0,
            }]),
            population: PopulationActorsConfig {
                actor_count: Some(6),
                service_ratio: Some(0.0),
                hot_actor_ratio: Some(0.0),
                hot_actor_multiplier: Some(1.0),
                account_ids: Some(vec!["123456789012".to_string()]),
                account_count: None,
                error_rate: None,
                human_error_rate: None,
                service_error_rate: None,
                role: None,
                service_events_per_hour: None,
                service_profiles: None,
                actor: None,
            },
        })
        .unwrap();
        let registry = IdentityRegistry::from_population("generated", &population).unwrap();

        assert_eq!(registry.identities().len(), 6);
        for identity in registry.identities() {
            assert!(identity.actor_id.starts_with("human-"));
            assert!(!identity.display_name.starts_with("Generated User"));
            assert!(identity.email.ends_with("@example.sg"));
            assert_eq!(identity.home_location, "Singapore");
            assert_eq!(
                identity.normal_countries_regions,
                vec!["Singapore".to_string()]
            );
            assert!(registry.resolve_email(&identity.email).is_some());
            assert!(registry
                .resolve_okta_user_id(&identity.okta_user_id)
                .is_some());
            assert!(registry
                .resolve_aws_arn(&identity.aws_principals[0].arn)
                .is_some());
        }
    }

    fn test_registry() -> IdentityRegistry {
        IdentityRegistry::new("test", vec![identity("user-001", "user@example.com")]).unwrap()
    }

    fn identity(actor_id: &str, email: &str) -> Identity {
        Identity {
            actor_id: actor_id.to_string(),
            email: email.to_string(),
            employee_id: "E-000001".to_string(),
            display_name: "Test User".to_string(),
            role_persona: "Test persona".to_string(),
            department: "Test Department".to_string(),
            home_location: "Test Location".to_string(),
            normal_countries_regions: vec!["Test Region".to_string()],
            okta_user_id: format!("okta-{actor_id}"),
            databricks_username: email.to_string(),
            aws_principals: vec![AwsPrincipal {
                account_id: "123456789012".to_string(),
                principal_id: format!("AIDA{actor_id}"),
                arn: format!("arn:aws:iam::123456789012:user/{actor_id}"),
                role_name: None,
                role_session_name: None,
                access_key_id: Some(format!("AKIA{actor_id}")),
            }],
            service_account: false,
            tags: Vec::new(),
            rate_per_hour: None,
        }
    }
}
