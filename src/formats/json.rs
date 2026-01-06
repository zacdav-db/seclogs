//! JSON sink for seclog events.
//!
//! Writes CloudTrail-style files per account/region and rotates by size or age.

use chrono::Utc;
use flate2::write::GzEncoder;
use flate2::Compression;
use rand::distributions::Alphanumeric;
use rand::Rng;
use crate::core::event::Event;
use crate::core::traits::EventWriter;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// JSON writer that buffers CloudTrail-style records per account/region.
pub struct JsonlWriter {
    dir: PathBuf,
    target_size_bytes: u64,
    max_age: Option<Duration>,
    compression: JsonlCompression,
    files: HashMap<RegionKey, RegionBuffer>,
}

#[derive(Debug, Clone, Copy)]
enum JsonlCompression {
    None,
    Gzip,
}

impl JsonlWriter {
    /// Creates a JSONL writer with size-based rotation and optional max age.
    pub fn new(
        dir: impl Into<PathBuf>,
        target_size_mb: u64,
        max_age_seconds: Option<u64>,
        compression: Option<&str>,
    ) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let max_age = max_age_seconds
            .and_then(|seconds| if seconds > 0 { Some(Duration::from_secs(seconds)) } else { None });
        let compression = parse_compression(compression)?;
        Ok(Self {
            dir,
            target_size_bytes: target_size_mb.saturating_mul(1024 * 1024),
            max_age,
            compression,
            files: HashMap::new(),
        })
    }
}

impl EventWriter for JsonlWriter {
    fn write_event(&mut self, event: &Event) -> io::Result<u64> {
        let record_bytes = record_bytes_for_event(event)?;
        let size = record_bytes.len() as u64;

        let context = file_context_from_event(event);
        let key = RegionKey {
            account_id: context.account_id,
            region: context.region,
        };

        let region = self
            .files
            .entry(key.clone())
            .or_insert_with(RegionBuffer::new);
        if region.current_size == 0 {
            region.first_event_at = Some(Instant::now());
        }
        append_record(region, &record_bytes);

        if region.current_size >= self.target_size_bytes {
            flush_region(&self.dir, &key, region, self.compression)?;
        }

        Ok(size)
    }

    fn flush(&mut self) -> io::Result<()> {
        let now = Instant::now();
        for (key, region) in self.files.iter_mut() {
            if region.current_size == 0 {
                continue;
            }
            if let Some(max_age) = self.max_age {
                let start = match region.first_event_at {
                    Some(start) => start,
                    None => {
                        region.first_event_at = Some(now);
                        continue;
                    }
                };
                if now.duration_since(start) < max_age {
                    continue;
                }
            }
            flush_region(&self.dir, key, region, self.compression)?;
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        for (key, region) in self.files.iter_mut() {
            if region.current_size > 0 {
                flush_region(&self.dir, key, region, self.compression)?;
            }
        }
        Ok(())
    }
}

struct FileContext {
    account_id: String,
    region: String,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct RegionKey {
    account_id: String,
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

fn open_region_file(
    dir: &Path,
    key: &RegionKey,
    compression: JsonlCompression,
) -> io::Result<File> {
    let stamp = current_stamp();
    let unique = unique_id();
    let ext = match compression {
        JsonlCompression::None => "json",
        JsonlCompression::Gzip => "json.gz",
    };
    let file = open_file(
        dir,
        &key.account_id,
        &key.region,
        &stamp,
        &unique,
        ext,
    )?;
    Ok(file)
}

fn open_file(
    dir: &Path,
    account_id: &str,
    region: &str,
    stamp: &str,
    unique: &str,
    ext: &str,
) -> io::Result<File> {
    let path = dir.join(format!(
        "{account_id}_CloudTrail_{region}_{stamp}_{unique}.{ext}"
    ));
    File::create(path)
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

fn file_context_from_event(event: &Event) -> FileContext {
    let account_id = event
        .envelope
        .tenant_id
        .clone()
        .unwrap_or_else(|| "000000000000".to_string());
    let region = event
        .payload
        .get("awsRegion")
        .or_else(|| event.payload.get("aws_region"))
        .and_then(|value| value.as_str())
        .unwrap_or("global")
        .to_string();

    FileContext { account_id, region }
}

fn flush_region(
    dir: &Path,
    key: &RegionKey,
    region: &mut RegionBuffer,
    compression: JsonlCompression,
) -> io::Result<()> {
    if region.current_size == 0 {
        return Ok(());
    }

    let file = open_region_file(dir, key, compression)?;
    match compression {
        JsonlCompression::None => {
            let mut file = file;
            file.write_all(&region.buffer)?;
            file.write_all(b"]}")?;
        }
        JsonlCompression::Gzip => {
            let mut encoder = GzEncoder::new(file, Compression::default());
            encoder.write_all(&region.buffer)?;
            encoder.write_all(b"]}")?;
            encoder.finish()?;
        }
    }
    region.buffer.clear();
    region.current_size = 0;
    region.first_event_at = None;
    region.record_count = 0;
    Ok(())
}

fn parse_compression(value: Option<&str>) -> io::Result<JsonlCompression> {
    let Some(value) = value else {
        return Ok(JsonlCompression::None);
    };
    let normalized = value.trim().to_lowercase();
    if normalized.is_empty() {
        return Ok(JsonlCompression::None);
    }
    match normalized.as_str() {
        "gzip" | "gz" => Ok(JsonlCompression::Gzip),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported jsonl compression: {value}"),
        )),
    }
}
