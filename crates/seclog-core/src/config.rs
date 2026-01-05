use serde::{Deserialize, Serialize};
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

/// Controls the global traffic profile for generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficConfig {
    /// Constant or realistic traffic mode.
    pub mode: TrafficMode,
    /// Target events per second (optional).
    pub events_per_second: Option<f64>,
    /// Target bytes per second (optional).
    pub bytes_per_second: Option<u64>,
    /// Optional curve definition for realistic mode.
    pub curve: Option<CurveConfig>,
    /// Optional timezone weighting for realistic mode.
    pub timezone_distribution: Option<Vec<TimezoneWeight>>,
}

/// Traffic generation mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficMode {
    Constant,
    Realistic,
}

/// Curve configuration for realistic traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CurveConfig {
    WeekdayPeak(WeekdayPeakCurve),
}

/// Weekday/weekend curve with local-hour peaks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeekdayPeakCurve {
    pub weekday_multiplier: f64,
    pub weekend_multiplier: f64,
    pub peak_hours_local: Vec<u8>,
    pub peak_multiplier: f64,
}

/// Weight for a timezone used in realistic traffic shaping.
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
    /// Rotation and flush settings.
    pub rotation: RotationConfig,
    /// Output format selection.
    pub format: FormatConfig,
}

/// Controls file rotation and flush behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    /// Target file size for rotation.
    pub target_size_mb: u64,
    /// Flush interval for writer buffers.
    pub flush_interval_ms: Option<u64>,
    /// Maximum age for a file before rotation.
    pub max_age_seconds: Option<u64>,
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
    /// Optional custom event weights.
    pub custom_events: Option<Vec<EventWeight>>,
    /// Total actor count to generate.
    pub actor_count: Option<usize>,
    /// Fraction of actors that are services.
    pub service_ratio: Option<f64>,
    /// Fraction of actors treated as "hot".
    pub hot_actor_ratio: Option<f64>,
    /// Share of events assigned to hot actors.
    pub hot_actor_share: Option<f64>,
    /// Explicit account IDs to sample from.
    pub account_ids: Option<Vec<String>>,
    /// Number of accounts to synthesize when `account_ids` is empty.
    pub account_count: Option<usize>,
    /// Optional path to an actor population Parquet file.
    pub actor_population_path: Option<String>,
    /// Per-event error injection settings.
    pub error_rates: Option<Vec<EventErrorConfig>>,
    /// Role distribution weights for human actors.
    pub role_distribution: Option<Vec<RoleWeight>>,
    /// Allowed regions.
    pub regions: Option<Vec<String>>,
    /// Optional region weighting for selection.
    pub region_distribution: Option<Vec<RegionWeight>>,
}

/// Event weight override for a specific event name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventWeight {
    pub name: String,
    pub weight: f64,
}

/// Error injection settings per event name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventErrorConfig {
    pub name: String,
    pub rate: f64,
    pub code: Option<String>,
    pub message: Option<String>,
}

/// Role weight for actor generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleWeight {
    pub name: String,
    pub weight: f64,
}

/// Region weight for event generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionWeight {
    pub name: String,
    pub weight: f64,
}
