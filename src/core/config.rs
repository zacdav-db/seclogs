use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;
use toml::Value as TomlValue;

/// Error while loading or parsing a config file.
#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(err) => write!(f, "config io error: {err}"),
            ConfigError::Parse(err) => write!(f, "config parse error: {err}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        ConfigError::Io(err)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(err: toml::de::Error) -> Self {
        ConfigError::Parse(err)
    }
}

/// Top-level generator configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Optional RNG seed for deterministic output.
    pub seed: Option<u64>,
    /// Traffic rate and shaping controls.
    pub traffic: TrafficConfig,
    /// Output sink configuration.
    pub output: OutputConfig,
    /// Source-specific configuration.
    pub source: SourceConfig,
}

impl Config {
    /// Loads a config file from TOML.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;
        Ok(toml::from_str(&contents)?)
    }
}

/// Controls the global simulation clock for generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficConfig {
    /// Optional start time for the simulated clock (RFC3339).
    pub start_time: Option<String>,
    /// Time scale multiplier (1.0 = real time, 60.0 = 1 minute per second).
    pub time_scale: Option<f64>,
}

/// Weight for a timezone used in actor population generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimezoneWeight {
    pub name: String,
    pub weight: f64,
}

/// Output sink configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OutputConfig {
    Zerobus(ZerobusOutputConfig),
    DatabricksVolume(DatabricksVolumeOutputConfig),
    File(FileOutputConfig),
}

impl OutputConfig {
    pub fn as_file(&self) -> Option<&FileOutputConfig> {
        match self {
            OutputConfig::File(config) => Some(config),
            OutputConfig::Zerobus(_) => None,
            OutputConfig::DatabricksVolume(_) => None,
        }
    }

    pub fn override_file_dir(&mut self, dir: String) -> Result<(), String> {
        match self {
            OutputConfig::File(config) => {
                config.dir = dir;
                Ok(())
            }
            OutputConfig::Zerobus(_) => {
                Err("--output can only override file output directories".to_string())
            }
            OutputConfig::DatabricksVolume(_) => {
                Err("--output can only override file output directories".to_string())
            }
        }
    }
}

/// File output sink configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOutputConfig {
    /// Output directory for generated files.
    pub dir: String,
    /// File write settings.
    pub files: FileConfig,
    /// Output format selection.
    pub format: FormatConfig,
}

/// Controls file output and flush behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileConfig {
    /// Target file size before a new file is started.
    pub target_size_mb: u64,
    /// Maximum age for a file before a new one is started.
    pub max_age_seconds: u64,
}

/// Output format selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FormatConfig {
    Jsonl(FormatOptions),
    Parquet(FormatOptions),
}

/// Per-format options (compression, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatOptions {
    pub compression: Option<String>,
}

/// Zerobus output sink configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZerobusOutputConfig {
    #[serde(rename = "type")]
    pub output_type: ZerobusOutputType,
    pub workspace_url: String,
    pub endpoint: String,
    #[serde(default = "default_zerobus_client_id_env")]
    pub client_id_env: String,
    #[serde(default = "default_zerobus_client_secret_env")]
    pub client_secret_env: String,
    #[serde(default = "default_zerobus_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_zerobus_max_inflight_requests")]
    pub max_inflight_requests: usize,
    #[serde(default = "default_zerobus_flush_interval_ms")]
    pub flush_interval_ms: u64,
    pub run_id: Option<String>,
    pub tables: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZerobusOutputType {
    Zerobus,
}

/// Databricks Unity Catalog volume output sink configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabricksVolumeOutputConfig {
    #[serde(rename = "type")]
    pub output_type: DatabricksVolumeOutputType,
    /// Databricks workspace URL, for example `https://dbc-...cloud.databricks.com`.
    pub workspace_url: String,
    /// Base UC volume directory, for example `/Volumes/main/seclog/raw/seclog`.
    pub volume_path: String,
    /// Environment variable containing a Databricks bearer token.
    #[serde(default = "default_databricks_volume_token_env")]
    pub token_env: String,
    /// Target uncompressed file size before upload.
    #[serde(default = "default_databricks_volume_target_size_mb")]
    pub target_size_mb: u64,
    /// Maximum buffered age before upload.
    #[serde(default = "default_databricks_volume_max_age_seconds")]
    pub max_age_seconds: u64,
    /// Periodic flush cadence used by the generator loop.
    #[serde(default = "default_databricks_volume_flush_interval_ms")]
    pub flush_interval_ms: u64,
    /// Optional compression for uploaded JSON files. Supported: `gzip`, `gz`.
    pub compression: Option<String>,
    /// Files API overwrite flag. Generated names are unique, so false is the safer default.
    #[serde(default)]
    pub overwrite: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatabricksVolumeOutputType {
    #[serde(
        rename = "databricks_volume",
        alias = "databricks_files",
        alias = "volume"
    )]
    DatabricksVolume,
}

fn default_zerobus_client_id_env() -> String {
    "DATABRICKS_CLIENT_ID".to_string()
}

fn default_zerobus_client_secret_env() -> String {
    "DATABRICKS_CLIENT_SECRET".to_string()
}

fn default_zerobus_batch_size() -> usize {
    500
}

fn default_zerobus_max_inflight_requests() -> usize {
    10_000
}

fn default_zerobus_flush_interval_ms() -> u64 {
    1_000
}

fn default_databricks_volume_token_env() -> String {
    "DATABRICKS_TOKEN".to_string()
}

fn default_databricks_volume_target_size_mb() -> u64 {
    50
}

fn default_databricks_volume_max_age_seconds() -> u64 {
    30
}

fn default_databricks_volume_flush_interval_ms() -> u64 {
    1_000
}

/// Source configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceConfig {
    #[serde(rename = "cloudtrail", alias = "cloud_trail")]
    CloudTrail(CloudTrailSourceConfig),
    #[serde(rename = "databricks_audit", alias = "databricks")]
    DatabricksAudit(DatabricksAuditSourceConfig),
    #[serde(rename = "okta", alias = "okta_system_log")]
    OktaSystemLog(OktaSystemLogSourceConfig),
    #[serde(rename = "multi", alias = "combined")]
    Multi(MultiSourceConfig),
}

/// CloudTrail-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTrailSourceConfig {
    /// Use curated event weights for CloudTrail.
    pub curated: bool,
    /// Optional path to an actor population Parquet file.
    pub actor_population_path: Option<String>,
    /// Optional path to a shared identity registry TOML file.
    pub identity_registry_path: Option<String>,
    /// Optional deterministic source IP pools for registry-backed rows, keyed by actor ID.
    pub baseline_source_ips: Option<HashMap<String, Vec<String>>>,
    /// Allowed regions.
    pub regions: Option<Vec<String>>,
    /// Optional region weighting for selection.
    pub region_distribution: Option<Vec<f64>>,
}

/// Composite source configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSourceConfig {
    /// Optional shared identity registry inherited by child sources.
    pub identity_registry_path: Option<String>,
    /// Child sources to run from one generator loop.
    #[serde(default, rename = "sources")]
    pub sources: Vec<SourceConfig>,
    /// Optional source-specific output sinks keyed by event envelope source.
    pub outputs: Option<HashMap<String, FileOutputConfig>>,
}

/// Databricks audit-log generation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabricksAuditSourceConfig {
    /// Path to a shared identity registry TOML file.
    #[serde(default)]
    pub identity_registry_path: String,
    /// Databricks account ID to place on generated audit rows.
    pub account_id: String,
    /// Workspace ID to place on generated audit rows.
    pub workspace_id: String,
    /// Optional finite number of normal baseline rows to emit for each identity.
    pub baseline_events_per_actor: Option<usize>,
    /// Optional deterministic source IP pools for baseline rows, keyed by actor ID.
    pub baseline_source_ips: Option<HashMap<String, Vec<String>>>,
    /// Deterministic audit events to inject into the stream.
    #[serde(default, rename = "event")]
    pub events: Vec<DatabricksAuditEventConfig>,
}

/// Explicit Databricks audit event injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabricksAuditEventConfig {
    pub actor_id: String,
    pub offset_seconds: Option<i64>,
    pub event_time: Option<String>,
    pub source_ip_address: String,
    pub service_name: String,
    pub action_name: String,
    pub request_params: Option<BTreeMap<String, String>>,
    pub response_status_code: i32,
    pub response_error_message: Option<String>,
    pub response_result: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub audit_level: Option<String>,
    pub source_geo_country: Option<String>,
    pub source_geo_region: Option<String>,
    pub source_geo_city: Option<String>,
}

/// Okta System Log generation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaSystemLogSourceConfig {
    /// Path to a shared identity registry TOML file.
    #[serde(default)]
    pub identity_registry_path: String,
    /// Optional Okta organization identifier used in the normalized envelope.
    pub org_id: Option<String>,
    /// Optional finite number of normal baseline rows to emit for each identity.
    pub baseline_events_per_actor: Option<usize>,
    /// Optional deterministic source IP pools for baseline rows, keyed by actor ID.
    pub baseline_source_ips: Option<HashMap<String, Vec<String>>>,
    /// Deterministic System Log events to inject into the stream.
    #[serde(default, rename = "event")]
    pub events: Vec<OktaSystemLogEventConfig>,
}

/// Explicit Okta System Log event injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaSystemLogEventConfig {
    pub actor_id: String,
    pub offset_seconds: Option<i64>,
    pub published: Option<String>,
    pub event_type: String,
    pub display_message: String,
    pub legacy_event_type: Option<String>,
    pub outcome_result: OktaOutcomeResult,
    pub outcome_reason: Option<String>,
    pub severity: Option<OktaSeverity>,
    pub source_ip_address: String,
    pub source_geo_country: Option<String>,
    pub source_geo_region: Option<String>,
    pub source_geo_city: Option<String>,
    pub source_geo_postal_code: Option<String>,
    pub source_geo_lat: Option<f64>,
    pub source_geo_lon: Option<f64>,
    pub user_agent: Option<String>,
    pub user_agent_browser: Option<String>,
    pub user_agent_os: Option<String>,
    pub client_device: Option<String>,
    pub client_id: Option<String>,
    pub client_zone: Option<String>,
    pub device: Option<OktaDeviceConfig>,
    pub authentication_provider: Option<String>,
    pub credential_provider: Option<String>,
    pub credential_type: Option<String>,
    pub external_session_id: Option<String>,
    pub transaction_id: Option<String>,
    pub transaction_type: Option<OktaTransactionType>,
    pub transaction_detail: Option<TomlValue>,
    pub actor_detail_entry: Option<TomlValue>,
    pub debug_data: Option<BTreeMap<String, TomlValue>>,
    pub security_context: Option<OktaSecurityContextConfig>,
    #[serde(default, rename = "target")]
    pub targets: Vec<OktaTargetConfig>,
}

/// Dynamic security context overrides for explicit Okta System Log events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaSecurityContextConfig {
    pub as_number: Option<i64>,
    pub as_org: Option<String>,
    pub bot_protection: Option<TomlValue>,
    pub domain: Option<String>,
    pub ip_details: Option<TomlValue>,
    pub isp: Option<String>,
    pub is_proxy: Option<bool>,
    pub risk: Option<TomlValue>,
    pub user_behaviors: Option<TomlValue>,
}

/// Explicit Okta device object overrides for System Log events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaDeviceConfig {
    pub id: Option<String>,
    pub name: Option<String>,
    pub os_platform: Option<String>,
    pub os_version: Option<String>,
    pub managed: Option<bool>,
    pub registered: Option<bool>,
    pub device_integrator: Option<String>,
    pub disk_encryption_type: Option<String>,
    pub screen_lock_type: Option<String>,
    pub jailbreak: Option<bool>,
    pub secure_hardware_present: Option<bool>,
}

/// Explicit Okta target entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaTargetConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub target_type: String,
    pub alternate_id: Option<String>,
    pub change_details: Option<TomlValue>,
    pub detail_entry: Option<TomlValue>,
    pub display_name: Option<String>,
}

/// Okta System Log outcome result values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OktaOutcomeResult {
    Success,
    Failure,
    Skipped,
    Allow,
    Deny,
    Challenge,
    Unknown,
    RateLimit,
    Deferred,
    Scheduled,
    Abandoned,
    Unanswered,
}

/// Okta System Log severity values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OktaSeverity {
    Debug,
    Error,
    Info,
    Warn,
}

/// Okta System Log transaction type values used by this generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OktaTransactionType {
    Web,
    Job,
}

/// Role weight for actor generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleWeight {
    pub name: String,
    pub weight: f64,
}

/// Actor population configuration (used for `seclog actors`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopulationConfig {
    /// Optional RNG seed for deterministic output.
    pub seed: Option<u64>,
    /// Optional timezone weighting for actor activity windows.
    pub timezone_distribution: Option<Vec<TimezoneWeight>>,
    /// Actor population parameters.
    pub population: PopulationActorsConfig,
}

impl PopulationConfig {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;
        Ok(toml::from_str(&contents)?)
    }
}

/// Actor population parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopulationActorsConfig {
    pub actor_count: Option<usize>,
    pub service_ratio: Option<f64>,
    pub hot_actor_ratio: Option<f64>,
    pub hot_actor_multiplier: Option<f64>,
    pub account_ids: Option<Vec<String>>,
    pub account_count: Option<usize>,
    pub error_rate: Option<ErrorRateConfig>,
    pub human_error_rate: Option<ErrorRateConfig>,
    pub service_error_rate: Option<ErrorRateConfig>,
    pub role: Option<Vec<RoleConfig>>,
    #[serde(rename = "service_events_per_hour", alias = "service_rate_per_hour")]
    pub service_events_per_hour: Option<f64>,
    pub service_profiles: Option<Vec<ServiceProfileConfig>>,
    /// Explicit actors with fixed traits and overrides.
    pub actor: Option<Vec<ExplicitActorConfig>>,
}

/// Per-role configuration entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    pub name: String,
    pub weight: f64,
    pub events_per_hour: f64,
}

/// Explicit actor overrides for population generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplicitActorConfig {
    pub id: String,
    pub kind: String,
    pub role: Option<String>,
    pub service_profile: Option<String>,
    pub service_pattern: Option<ServicePatternConfig>,
    pub events_per_hour: Option<f64>,
    pub error_rate: Option<f64>,
    pub account_id: Option<String>,
    pub user_name: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub home_location: Option<String>,
    pub normal_countries_regions: Option<Vec<String>>,
    pub principal_id: Option<String>,
    pub arn: Option<String>,
    pub access_key_id: Option<String>,
    pub identity_type: Option<String>,
    pub timezone: Option<String>,
    pub active_start_hour: Option<u8>,
    pub active_hours: Option<u8>,
    pub weekend_active: Option<bool>,
    pub user_agents: Option<Vec<String>>,
    pub source_ips: Option<Vec<String>>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub event_bias: HashMap<String, f64>,
}

/// Error rate range configuration for actor populations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRateConfig {
    pub min: f64,
    pub max: f64,
    pub distribution: Option<ErrorRateDistribution>,
}

/// Distribution used to sample error rates within a range.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorRateDistribution {
    Uniform,
    Normal,
}

/// Service actor profile distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceProfileConfig {
    pub name: String,
    pub weight: f64,
    #[serde(rename = "events_per_hour", alias = "rate_per_hour")]
    pub events_per_hour: Option<f64>,
    pub pattern: Option<ServicePatternConfig>,
}

/// Service activity pattern for scheduling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServicePatternConfig {
    Constant,
    Diurnal,
    Bursty,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_sources_example_uses_shared_registry_and_routed_outputs() {
        let config = Config::from_path("examples/all_sources.toml").unwrap();
        assert!(matches!(&config.output, OutputConfig::File(_)));

        let SourceConfig::Multi(source) = config.source else {
            panic!("expected multi source");
        };

        assert_eq!(
            source.identity_registry_path.as_deref(),
            Some("./examples/identity_registry.toml")
        );
        assert_eq!(source.sources.len(), 3);

        let output_keys = source.outputs.unwrap();
        assert!(output_keys.contains_key("cloudtrail"));
        assert!(output_keys.contains_key("databricks_audit"));
        assert!(output_keys.contains_key("okta_system_log"));

        assert!(matches!(&source.sources[0], SourceConfig::CloudTrail(_)));
        assert!(matches!(
            &source.sources[1],
            SourceConfig::DatabricksAudit(_)
        ));
        assert!(matches!(&source.sources[2], SourceConfig::OktaSystemLog(_)));
    }

    #[test]
    fn zerobus_example_uses_source_table_routes() {
        let config = Config::from_path("examples/all_sources_zerobus.toml").unwrap();
        let OutputConfig::Zerobus(output) = config.output else {
            panic!("expected zerobus output");
        };

        assert_eq!(output.output_type, ZerobusOutputType::Zerobus);
        assert_eq!(output.client_id_env, "DATABRICKS_CLIENT_ID");
        assert_eq!(output.client_secret_env, "DATABRICKS_CLIENT_SECRET");
        assert_eq!(output.batch_size, 500);
        assert_eq!(output.max_inflight_requests, 10_000);
        assert_eq!(
            output.tables.get("cloudtrail").map(String::as_str),
            Some("main.seclog.cloudtrail_events")
        );
        assert_eq!(
            output.tables.get("databricks_audit").map(String::as_str),
            Some("main.seclog.databricks_audit_events")
        );
        assert_eq!(
            output.tables.get("okta_system_log").map(String::as_str),
            Some("main.seclog.okta_system_log_events")
        );
        assert_eq!(
            output.tables.get("actor_population").map(String::as_str),
            Some("main.seclog.actor_population")
        );
    }

    #[test]
    fn databricks_volume_example_uses_files_api_output() {
        let config = Config::from_path("examples/all_sources_volume.toml").unwrap();
        let OutputConfig::DatabricksVolume(output) = config.output else {
            panic!("expected databricks volume output");
        };

        assert_eq!(
            output.output_type,
            DatabricksVolumeOutputType::DatabricksVolume
        );
        assert_eq!(
            output.workspace_url,
            "https://dbc-example.cloud.databricks.com"
        );
        assert_eq!(output.volume_path, "/Volumes/main/seclog/raw/seclog");
        assert_eq!(output.token_env, "DATABRICKS_TOKEN");
        assert_eq!(output.target_size_mb, 50);
        assert_eq!(output.max_age_seconds, 30);
        assert_eq!(output.flush_interval_ms, 1_000);
        assert_eq!(output.compression.as_deref(), Some("gzip"));
        assert!(!output.overwrite);
    }
}
