use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub seed: Option<u64>,
    pub traffic: TrafficConfig,
    pub output: OutputConfig,
    pub source: SourceConfig,
}

impl Config {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;
        Ok(toml::from_str(&contents)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficConfig {
    pub mode: TrafficMode,
    pub events_per_second: Option<f64>,
    pub bytes_per_second: Option<u64>,
    pub curve: Option<CurveConfig>,
    pub timezone_distribution: Option<Vec<TimezoneWeight>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficMode {
    Constant,
    Realistic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CurveConfig {
    WeekdayPeak(WeekdayPeakCurve),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeekdayPeakCurve {
    pub weekday_multiplier: f64,
    pub weekend_multiplier: f64,
    pub peak_hours_local: Vec<u8>,
    pub peak_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimezoneWeight {
    pub name: String,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub dir: String,
    pub rotation: RotationConfig,
    pub format: FormatConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    pub target_size_mb: u64,
    pub flush_interval_ms: Option<u64>,
    pub max_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FormatConfig {
    Jsonl(FormatOptions),
    Parquet(FormatOptions),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatOptions {
    pub compression: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceConfig {
    #[serde(rename = "cloudtrail", alias = "cloud_trail")]
    CloudTrail(CloudTrailSourceConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTrailSourceConfig {
    pub curated: bool,
    pub custom_events: Option<Vec<EventWeight>>,
    pub actor_count: Option<usize>,
    pub service_ratio: Option<f64>,
    pub hot_actor_ratio: Option<f64>,
    pub hot_actor_share: Option<f64>,
    pub account_ids: Option<Vec<String>>,
    pub account_count: Option<usize>,
    pub actor_population_path: Option<String>,
    pub error_rates: Option<Vec<EventErrorConfig>>,
    pub role_distribution: Option<Vec<RoleWeight>>,
    pub regions: Option<Vec<String>>,
    pub region_distribution: Option<Vec<RegionWeight>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventWeight {
    pub name: String,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventErrorConfig {
    pub name: String,
    pub rate: f64,
    pub code: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleWeight {
    pub name: String,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionWeight {
    pub name: String,
    pub weight: f64,
}
