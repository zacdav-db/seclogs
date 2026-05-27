//! Databricks Unity Catalog volume output sink.
//!
//! Buffers source-native JSON record files and uploads them to a UC volume with
//! the Databricks Files API. This is a file sink; it does not create or mutate
//! Delta tables.

use crate::core::config::DatabricksVolumeOutputConfig;
use crate::core::event::Event;
use crate::core::traits::EventWriter;
use chrono::Utc;
use flate2::write::GzEncoder;
use flate2::Compression;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::env;
use std::io::{self, Write};
use std::time::{Duration, Instant};

const MAX_FILES_API_UPLOAD_MB: u64 = 5 * 1024;

/// Databricks volume writer used by the CLI.
pub struct DatabricksVolumeWriter {
    inner: PlatformDatabricksVolumeWriter,
}

impl DatabricksVolumeWriter {
    pub fn new(config: &DatabricksVolumeOutputConfig) -> io::Result<Self> {
        Ok(Self {
            inner: build_platform_writer(config)?,
        })
    }
}

impl EventWriter for DatabricksVolumeWriter {
    fn write_event(&mut self, event: &Event) -> io::Result<u64> {
        self.inner.write_event(event)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    fn close(&mut self) -> io::Result<()> {
        self.inner.close()
    }
}

#[cfg(feature = "databricks_volume")]
type PlatformDatabricksVolumeWriter = VolumeFileWriter<RealVolumeFilesClient>;

#[cfg(not(feature = "databricks_volume"))]
struct PlatformDatabricksVolumeWriter;

#[cfg(feature = "databricks_volume")]
fn build_platform_writer(
    config: &DatabricksVolumeOutputConfig,
) -> io::Result<PlatformDatabricksVolumeWriter> {
    let client = RealVolumeFilesClient::from_config(config)?;
    VolumeFileWriter::new(config, client)
}

#[cfg(not(feature = "databricks_volume"))]
fn build_platform_writer(
    config: &DatabricksVolumeOutputConfig,
) -> io::Result<PlatformDatabricksVolumeWriter> {
    PlatformDatabricksVolumeWriter::new(config)
}

#[cfg(not(feature = "databricks_volume"))]
impl PlatformDatabricksVolumeWriter {
    fn new(_config: &DatabricksVolumeOutputConfig) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "databricks_volume output requires building with --features databricks_volume",
        ))
    }

    fn write_event(&mut self, _event: &Event) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "databricks_volume output requires building with --features databricks_volume",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

trait VolumeFilesClient {
    fn create_directory(&mut self, path: &str) -> io::Result<()>;
    fn upload_file(&mut self, path: &str, bytes: Vec<u8>, overwrite: bool) -> io::Result<()>;
}

struct VolumeFileWriter<C: VolumeFilesClient> {
    client: C,
    base_path: String,
    target_size_bytes: u64,
    max_age: Option<Duration>,
    compression: VolumeCompression,
    overwrite: bool,
    files: HashMap<RegionKey, RegionBuffer>,
    ensured_directories: HashSet<String>,
}

#[derive(Debug, Clone, Copy)]
enum VolumeCompression {
    None,
    Gzip,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct RegionKey {
    source: String,
    tenant_id: String,
    region: String,
}

struct RegionBuffer {
    current_size: u64,
    buffer: Vec<u8>,
    first_event_at: Option<Instant>,
    record_count: u64,
}

impl RegionBuffer {
    fn new() -> Self {
        Self {
            current_size: 0,
            buffer: Vec::new(),
            first_event_at: None,
            record_count: 0,
        }
    }
}

impl<C: VolumeFilesClient> VolumeFileWriter<C> {
    fn new(config: &DatabricksVolumeOutputConfig, client: C) -> io::Result<Self> {
        validate_target_size(config.target_size_mb)?;
        let base_path = normalize_volume_path(&config.volume_path)?;
        let max_age = if config.max_age_seconds > 0 {
            Some(Duration::from_secs(config.max_age_seconds))
        } else {
            None
        };
        Ok(Self {
            client,
            base_path,
            target_size_bytes: config.target_size_mb.saturating_mul(1024 * 1024),
            max_age,
            compression: parse_compression(config.compression.as_deref())?,
            overwrite: config.overwrite,
            files: HashMap::new(),
            ensured_directories: HashSet::new(),
        })
    }

    fn write_event(&mut self, event: &Event) -> io::Result<u64> {
        let record_bytes = record_bytes_for_event(event)?;
        let size = record_bytes.len() as u64;
        let key = region_key_from_event(event);
        let region = self
            .files
            .entry(key.clone())
            .or_insert_with(RegionBuffer::new);
        if region.current_size == 0 {
            region.first_event_at = Some(Instant::now());
        }
        append_record(region, &record_bytes);

        if region.current_size >= self.target_size_bytes {
            self.flush_region(&key)?;
        }

        Ok(size)
    }

    fn flush(&mut self) -> io::Result<()> {
        let now = Instant::now();
        let mut ready = Vec::new();
        for (key, region) in &mut self.files {
            if region.current_size == 0 {
                continue;
            }
            let Some(max_age) = self.max_age else {
                ready.push(key.clone());
                continue;
            };
            let start = match region.first_event_at {
                Some(start) => start,
                None => {
                    region.first_event_at = Some(now);
                    continue;
                }
            };
            if now.duration_since(start) >= max_age {
                ready.push(key.clone());
            }
        }

        for key in ready {
            self.flush_region(&key)?;
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        let keys = self.files.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            self.flush_region(&key)?;
        }
        Ok(())
    }

    fn flush_region(&mut self, key: &RegionKey) -> io::Result<()> {
        let bytes = {
            let Some(region) = self.files.get(key) else {
                return Ok(());
            };
            if region.current_size == 0 {
                return Ok(());
            }
            finalize_region_bytes(region, self.compression)?
        };
        let path = remote_file_path(&self.base_path, key, self.compression);
        let parent = parent_path(&path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("databricks volume file path has no parent: {path}"),
            )
        })?;
        self.ensure_directory(&parent)?;
        self.client.upload_file(&path, bytes, self.overwrite)?;
        if let Some(region) = self.files.get_mut(key) {
            region.buffer.clear();
            region.current_size = 0;
            region.first_event_at = None;
            region.record_count = 0;
        }
        Ok(())
    }

    fn ensure_directory(&mut self, path: &str) -> io::Result<()> {
        for directory in subdirectories_below_volume_root(path)? {
            if self.ensured_directories.insert(directory.clone()) {
                self.client.create_directory(&directory)?;
            }
        }
        Ok(())
    }
}

fn validate_target_size(target_size_mb: u64) -> io::Result<()> {
    if target_size_mb > MAX_FILES_API_UPLOAD_MB {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "databricks_volume target_size_mb must be <= {MAX_FILES_API_UPLOAD_MB} because the Files API upload limit is 5 GiB"
            ),
        ));
    }
    Ok(())
}

fn record_bytes_for_event(event: &Event) -> io::Result<Vec<u8>> {
    if event.payload.is_null() {
        serde_json::to_vec(event).map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    } else {
        serde_json::to_vec(&event.payload).map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }
}

fn append_record(region: &mut RegionBuffer, record_bytes: &[u8]) {
    if region.record_count == 0 {
        region.buffer.extend_from_slice(b"{\"Records\":[");
    } else {
        region.buffer.push(b',');
    }
    region.buffer.extend_from_slice(record_bytes);
    region.record_count += 1;
    region.current_size = region.buffer.len() as u64 + 2;
}

fn finalize_region_bytes(
    region: &RegionBuffer,
    compression: VolumeCompression,
) -> io::Result<Vec<u8>> {
    let mut body = region.buffer.clone();
    body.extend_from_slice(b"]}");
    match compression {
        VolumeCompression::None => Ok(body),
        VolumeCompression::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&body)?;
            encoder.finish()
        }
    }
}

fn region_key_from_event(event: &Event) -> RegionKey {
    let tenant_id = event
        .envelope
        .tenant_id
        .clone()
        .unwrap_or_else(|| "unknown-tenant".to_string());
    let region = event
        .payload
        .get("awsRegion")
        .or_else(|| event.payload.get("aws_region"))
        .and_then(|value| value.as_str())
        .unwrap_or("global")
        .to_string();

    RegionKey {
        source: event.envelope.source.clone(),
        tenant_id,
        region,
    }
}

fn remote_file_path(base_path: &str, key: &RegionKey, compression: VolumeCompression) -> String {
    let stamp = current_stamp();
    let unique = unique_id();
    let source = safe_path_segment(&key.source);
    let tenant_id = safe_path_segment(&key.tenant_id);
    let region = safe_path_segment(&key.region);
    let ext = match compression {
        VolumeCompression::None => "json",
        VolumeCompression::Gzip => "json.gz",
    };
    format!(
        "{base_path}/source={source}/tenant_id={tenant_id}/region={region}/{tenant_id}_{source}_{region}_{stamp}_{unique}.{ext}"
    )
}

fn current_stamp() -> String {
    let now = Utc::now();
    format!("{}", now.format("%Y%m%dT%H%MZ"))
}

fn unique_id() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect::<String>()
        .to_lowercase()
}

fn parse_compression(value: Option<&str>) -> io::Result<VolumeCompression> {
    let Some(value) = value else {
        return Ok(VolumeCompression::None);
    };
    let normalized = value.trim().to_lowercase();
    if normalized.is_empty() || normalized == "none" {
        return Ok(VolumeCompression::None);
    }
    match normalized.as_str() {
        "gzip" | "gz" => Ok(VolumeCompression::Gzip),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported databricks_volume compression: {value}"),
        )),
    }
}

fn normalize_volume_path(path: &str) -> io::Result<String> {
    let trimmed = path.trim().trim_end_matches('/');
    let without_scheme = trimmed.strip_prefix("dbfs:").unwrap_or(trimmed);
    if !without_scheme.starts_with("/Volumes/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "databricks_volume volume_path must start with /Volumes/<catalog>/<schema>/<volume> or dbfs:/Volumes/..."
            ),
        ));
    }
    let part_count = without_scheme
        .split('/')
        .filter(|part| !part.is_empty())
        .count();
    if part_count < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "databricks_volume volume_path must include catalog, schema, and volume".to_string(),
        ));
    }
    Ok(without_scheme.to_string())
}

fn parent_path(path: &str) -> Option<String> {
    path.rsplit_once('/').map(|(parent, _)| parent.to_string())
}

fn subdirectories_below_volume_root(path: &str) -> io::Result<Vec<String>> {
    let normalized = normalize_volume_path(path)?;
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() <= 4 {
        return Ok(Vec::new());
    }

    let mut current = format!("/{}/{}/{}/{}", parts[0], parts[1], parts[2], parts[3]);
    let mut directories = Vec::new();
    for part in &parts[4..] {
        current.push('/');
        current.push_str(part);
        directories.push(current.clone());
    }
    Ok(directories)
}

fn safe_path_segment(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn read_required_env(name: &str, label: &str) -> io::Result<String> {
    let value = env::var(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("databricks_volume {label} env var {name} is not set"),
        )
    })?;
    if value.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("databricks_volume {label} env var {name} is empty"),
        ));
    }
    Ok(value)
}

fn encode_api_path(path: &str) -> String {
    path.split('/')
        .map(percent_encode_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn percent_encode_path_segment(segment: &str) -> String {
    let mut encoded = String::new();
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn files_api_url(
    workspace_url: &str,
    endpoint: &str,
    volume_path: &str,
    overwrite: Option<bool>,
) -> String {
    let mut url = format!(
        "{}/api/2.0/fs/{}{}",
        workspace_url.trim_end_matches('/'),
        endpoint,
        encode_api_path(volume_path)
    );
    if let Some(overwrite) = overwrite {
        url.push_str(if overwrite {
            "?overwrite=true"
        } else {
            "?overwrite=false"
        });
    }
    url
}

#[cfg(feature = "databricks_volume")]
struct RealVolumeFilesClient {
    workspace_url: String,
    token: String,
    client: reqwest::blocking::Client,
}

#[cfg(feature = "databricks_volume")]
impl RealVolumeFilesClient {
    fn from_config(config: &DatabricksVolumeOutputConfig) -> io::Result<Self> {
        let token = read_required_env(&config.token_env, "token")?;
        let client = reqwest::blocking::Client::builder()
            .build()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        Ok(Self {
            workspace_url: config.workspace_url.clone(),
            token,
            client,
        })
    }

    fn put_empty(&self, endpoint: &str, path: &str) -> io::Result<()> {
        let url = files_api_url(&self.workspace_url, endpoint, path, None);
        let response = self
            .client
            .put(url)
            .bearer_auth(&self.token)
            .send()
            .map_err(map_reqwest_error)?;
        check_response(response, "create directory", path)
    }
}

#[cfg(feature = "databricks_volume")]
impl VolumeFilesClient for RealVolumeFilesClient {
    fn create_directory(&mut self, path: &str) -> io::Result<()> {
        self.put_empty("directories", path)
    }

    fn upload_file(&mut self, path: &str, bytes: Vec<u8>, overwrite: bool) -> io::Result<()> {
        let url = files_api_url(&self.workspace_url, "files", path, Some(overwrite));
        let response = self
            .client
            .put(url)
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(bytes)
            .send()
            .map_err(map_reqwest_error)?;
        check_response(response, "upload file", path)
    }
}

#[cfg(feature = "databricks_volume")]
fn check_response(
    response: reqwest::blocking::Response,
    operation: &str,
    path: &str,
) -> io::Result<()> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let body = response.text().unwrap_or_else(|_| "".to_string());
    let body = body.trim();
    let detail = if body.is_empty() {
        status.to_string()
    } else {
        format!("{status}: {body}")
    };
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("databricks_volume Files API {operation} failed for {path}: {detail}"),
    ))
}

#[cfg(feature = "databricks_volume")]
fn map_reqwest_error(err: reqwest::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("databricks_volume Files API request failed: {err}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{Actor, EventEnvelope, Outcome};
    use flate2::read::GzDecoder;
    use serde_json::{json, Value};
    use std::cell::RefCell;
    use std::io::Read;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct FakeClient {
        state: Rc<RefCell<FakeState>>,
    }

    #[derive(Default)]
    struct FakeState {
        directories: Vec<String>,
        uploads: Vec<(String, Vec<u8>, bool)>,
    }

    impl VolumeFilesClient for FakeClient {
        fn create_directory(&mut self, path: &str) -> io::Result<()> {
            self.state.borrow_mut().directories.push(path.to_string());
            Ok(())
        }

        fn upload_file(&mut self, path: &str, bytes: Vec<u8>, overwrite: bool) -> io::Result<()> {
            self.state
                .borrow_mut()
                .uploads
                .push((path.to_string(), bytes, overwrite));
            Ok(())
        }
    }

    #[test]
    fn routes_events_to_per_source_volume_paths() {
        let state = Rc::new(RefCell::new(FakeState::default()));
        let config = test_config(None);
        let client = FakeClient {
            state: state.clone(),
        };
        let mut writer = VolumeFileWriter::new(&config, client).unwrap();

        writer
            .write_event(&test_event("cloudtrail", "ConsoleLogin"))
            .unwrap();
        writer
            .write_event(&test_event("databricks_audit", "IpAccessDenied"))
            .unwrap();
        writer
            .write_event(&test_event("okta_system_log", "user.session.start"))
            .unwrap();
        writer.close().unwrap();

        let state = state.borrow();
        assert_eq!(state.uploads.len(), 3);
        let paths = state
            .uploads
            .iter()
            .map(|(path, _, _)| path.as_str())
            .collect::<Vec<_>>();
        assert!(paths
            .iter()
            .any(|path| path.contains("/source=cloudtrail/")));
        assert!(paths
            .iter()
            .any(|path| path.contains("/source=databricks_audit/")));
        assert!(paths
            .iter()
            .any(|path| path.contains("/source=okta_system_log/")));
        assert!(state
            .directories
            .iter()
            .any(|path| path.contains("/source=cloudtrail/tenant_id=tenant-1/region=us-east-1")));
    }

    #[test]
    fn batches_records_until_close_and_preserves_payload() {
        let state = Rc::new(RefCell::new(FakeState::default()));
        let config = test_config(None);
        let client = FakeClient {
            state: state.clone(),
        };
        let mut writer = VolumeFileWriter::new(&config, client).unwrap();

        writer
            .write_event(&test_event("cloudtrail", "ConsoleLogin"))
            .unwrap();
        writer
            .write_event(&test_event("cloudtrail", "AssumeRole"))
            .unwrap();
        writer.close().unwrap();

        let state = state.borrow();
        assert_eq!(state.uploads.len(), 1);
        assert!(!state.uploads[0].2);
        let body = std::str::from_utf8(&state.uploads[0].1).unwrap();
        let value: Value = serde_json::from_str(body).unwrap();
        assert_eq!(value["Records"].as_array().unwrap().len(), 2);
        assert_eq!(value["Records"][0]["eventName"], "ConsoleLogin");
        assert_eq!(value["Records"][1]["eventName"], "AssumeRole");
    }

    #[test]
    fn gzip_compression_uploads_gzip_json() {
        let state = Rc::new(RefCell::new(FakeState::default()));
        let config = test_config(Some("gzip"));
        let client = FakeClient {
            state: state.clone(),
        };
        let mut writer = VolumeFileWriter::new(&config, client).unwrap();

        writer
            .write_event(&test_event("cloudtrail", "ConsoleLogin"))
            .unwrap();
        writer.close().unwrap();

        let state = state.borrow();
        assert_eq!(state.uploads.len(), 1);
        assert!(state.uploads[0].0.ends_with(".json.gz"));
        assert_eq!(&state.uploads[0].1[0..2], &[0x1f, 0x8b]);

        let mut decoder = GzDecoder::new(&state.uploads[0].1[..]);
        let mut decoded = String::new();
        decoder.read_to_string(&mut decoded).unwrap();
        let value: Value = serde_json::from_str(&decoded).unwrap();
        assert_eq!(value["Records"][0]["eventName"], "ConsoleLogin");
    }

    #[test]
    fn normalizes_uc_volume_paths() {
        assert_eq!(
            normalize_volume_path("dbfs:/Volumes/main/seclog/raw/path/").unwrap(),
            "/Volumes/main/seclog/raw/path"
        );
        assert_eq!(
            normalize_volume_path("/Volumes/main/seclog/raw").unwrap(),
            "/Volumes/main/seclog/raw"
        );
        assert!(normalize_volume_path("/tmp/seclog").is_err());
        assert!(normalize_volume_path("/Volumes/main/seclog").is_err());
    }

    #[test]
    fn creates_only_directories_below_volume_root() {
        let directories = subdirectories_below_volume_root(
            "/Volumes/main/seclog/raw/seclog/source=cloudtrail/tenant_id=tenant-1",
        )
        .unwrap();
        assert_eq!(
            directories,
            vec![
                "/Volumes/main/seclog/raw/seclog".to_string(),
                "/Volumes/main/seclog/raw/seclog/source=cloudtrail".to_string(),
                "/Volumes/main/seclog/raw/seclog/source=cloudtrail/tenant_id=tenant-1".to_string()
            ]
        );
        assert!(subdirectories_below_volume_root("/Volumes/main/seclog/raw")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn files_api_url_matches_databricks_path_shape() {
        let url = files_api_url(
            "https://dbc-example.cloud.databricks.com/",
            "files",
            "/Volumes/main/default/my-volume/source=okta system/file one.json",
            Some(false),
        );
        assert_eq!(
            url,
            "https://dbc-example.cloud.databricks.com/api/2.0/fs/files/Volumes/main/default/my-volume/source%3Dokta%20system/file%20one.json?overwrite=false"
        );
    }

    #[test]
    fn rejects_files_api_upload_targets_over_five_gib() {
        let mut config = test_config(None);
        config.target_size_mb = 5 * 1024 + 1;
        let err = VolumeFileWriter::new(&config, FakeClient::default())
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "databricks_volume target_size_mb must be <= 5120 because the Files API upload limit is 5 GiB"
        );
    }

    #[test]
    fn missing_token_env_var_is_redacted() {
        env::remove_var("SECLOG_TEST_MISSING_DATABRICKS_TOKEN");
        let err = read_required_env("SECLOG_TEST_MISSING_DATABRICKS_TOKEN", "token").unwrap_err();
        assert_eq!(
            err.to_string(),
            "databricks_volume token env var SECLOG_TEST_MISSING_DATABRICKS_TOKEN is not set"
        );
    }

    #[cfg(not(feature = "databricks_volume"))]
    #[test]
    fn platform_writer_requires_feature() {
        let err = DatabricksVolumeWriter::new(&test_config(None))
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "databricks_volume output requires building with --features databricks_volume"
        );
    }

    fn test_config(compression: Option<&str>) -> DatabricksVolumeOutputConfig {
        DatabricksVolumeOutputConfig {
            output_type: crate::core::config::DatabricksVolumeOutputType::DatabricksVolume,
            workspace_url: "https://dbc-example.cloud.databricks.com".to_string(),
            volume_path: "/Volumes/main/seclog/raw/seclog".to_string(),
            token_env: "DATABRICKS_TOKEN".to_string(),
            target_size_mb: 50,
            max_age_seconds: 30,
            flush_interval_ms: 1_000,
            compression: compression.map(str::to_string),
            overwrite: false,
        }
    }

    fn test_event(source: &str, event_type: &str) -> Event {
        Event {
            envelope: EventEnvelope {
                schema_version: "v1".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                source: source.to_string(),
                event_type: event_type.to_string(),
                actor: Actor {
                    id: "user-001".to_string(),
                    kind: "human".to_string(),
                    name: Some("Amelia Chen".to_string()),
                },
                target: None,
                outcome: Outcome::Success,
                geo: None,
                ip: Some("198.51.100.10".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
                session_id: Some("session-1".to_string()),
                tenant_id: Some("tenant-1".to_string()),
            },
            payload: json!({
                "eventName": event_type,
                "awsRegion": "us-east-1"
            }),
        }
    }
}
