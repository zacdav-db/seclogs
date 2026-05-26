//! Shared identity registry support for cross-source generators.
//!
//! The registry is intentionally data-driven. Scenario-specific people,
//! service accounts, and platform identifiers should live in registry files,
//! while generators consume the normalized identities through this module.

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        }
    }
}
