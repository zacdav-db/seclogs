use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

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
pub struct OutputConfig {
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

/// Source configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceConfig {
    #[serde(rename = "cloudtrail", alias = "cloud_trail")]
    CloudTrail(CloudTrailSourceConfig),
}

/// CloudTrail-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTrailSourceConfig {
    /// Use curated event weights for CloudTrail.
    pub curated: bool,
    /// Optional path to an actor population Parquet file.
    pub actor_population_path: Option<String>,
    /// Allowed regions.
    pub regions: Option<Vec<String>>,
    /// Optional region weighting for selection.
    pub region_distribution: Option<Vec<f64>>,
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
