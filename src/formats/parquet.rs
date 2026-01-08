//! Parquet sink for seclog events.
//!
//! Buffers Arrow batches per account/region and rotates by size or age.

use arrow_array::builder::{BooleanBuilder, Float64Builder, StringBuilder, StructBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef};
use chrono::Utc;
use parquet::arrow::arrow_writer::ArrowWriter;
use parquet::errors::ParquetError;
use parquet::file::properties::WriterProperties;
use crate::core::event::{Actor, Event, Geo, Outcome, Target};
use crate::core::traits::EventWriter;
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde_json::Value;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_BATCH_SIZE: usize = 1024;

/// Parquet writer that buffers events per account/region.
pub struct ParquetWriter {
    dir: PathBuf,
    target_size_bytes: u64,
    schema: SchemaRef,
    batch_size: usize,
    max_age: Option<Duration>,
    regions: HashMap<RegionKey, RegionState>,
    file_prefix: Option<String>,
}

impl ParquetWriter {
    /// Creates a Parquet writer with the default batch size.
    pub fn new(
        dir: impl Into<PathBuf>,
        target_size_mb: u64,
        max_age_seconds: Option<u64>,
    ) -> io::Result<Self> {
        Self::with_batch_size(dir, target_size_mb, max_age_seconds, DEFAULT_BATCH_SIZE, None)
    }

    /// Creates a Parquet writer with a prefix applied to file names.
    pub fn with_prefix(
        dir: impl Into<PathBuf>,
        target_size_mb: u64,
        max_age_seconds: Option<u64>,
        prefix: impl Into<String>,
    ) -> io::Result<Self> {
        Self::with_batch_size(
            dir,
            target_size_mb,
            max_age_seconds,
            DEFAULT_BATCH_SIZE,
            Some(prefix.into()),
        )
    }

    /// Creates a Parquet writer with a custom batch size.
    pub fn with_batch_size(
        dir: impl Into<PathBuf>,
        target_size_mb: u64,
        max_age_seconds: Option<u64>,
        batch_size: usize,
        file_prefix: Option<String>,
    ) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let schema = build_schema();
        let max_age = max_age_seconds
            .and_then(|seconds| if seconds > 0 { Some(Duration::from_secs(seconds)) } else { None });
        Ok(Self {
            dir,
            target_size_bytes: target_size_mb.saturating_mul(1024 * 1024),
            schema,
            batch_size,
            max_age,
            regions: HashMap::new(),
            file_prefix,
        })
    }

}

impl EventWriter for ParquetWriter {
    fn write_event(&mut self, event: &Event) -> io::Result<u64> {
        let payload_json = if event.payload.is_null() {
            None
        } else {
            Some(
                serde_json::to_string(&event.payload)
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?,
            )
        };

        let size = estimate_event_size(event, payload_json.as_deref());
        let context = file_context_from_event(event);
        let key = RegionKey {
            account_id: context.account_id,
            region: context.region,
        };
        let state = self
            .regions
            .entry(key.clone())
            .or_insert_with(|| RegionState::new(self.schema.clone(), self.batch_size));

        if state.current_size == 0 {
            state.first_event_at = Some(Instant::now());
        }
        state
            .batch
            .append_event(event, payload_json.as_deref())
            .map_err(map_arrow_err)?;
        state.current_size += size;

        if state.current_size >= self.target_size_bytes {
            flush_region(
                &self.dir,
                &self.schema,
                self.file_prefix.as_deref(),
                &key,
                state,
            )?;
        }

        Ok(size)
    }

    fn flush(&mut self) -> io::Result<()> {
        let now = Instant::now();
        for (key, state) in self.regions.iter_mut() {
            if state.current_size > 0 {
                if let Some(max_age) = self.max_age {
                    let start = match state.first_event_at {
                        Some(start) => start,
                        None => {
                            state.first_event_at = Some(now);
                            continue;
                        }
                    };
                    if now.duration_since(start) < max_age {
                        continue;
                    }
                }
                flush_region(
                    &self.dir,
                    &self.schema,
                    self.file_prefix.as_deref(),
                    key,
                    state,
                )?;
            }
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        self.flush()
    }
}

struct EventBatchBuilder {
    schema: SchemaRef,
    envelope: StructBuilder,
    payload_json: StringBuilder,
    cloudtrail: StructBuilder,
    len: usize,
}

impl EventBatchBuilder {
    fn new(schema: SchemaRef, capacity: usize) -> Self {
        let envelope_fields = match schema.field(0).data_type() {
            DataType::Struct(fields) => fields.clone(),
            _ => Fields::empty(),
        };
        let cloudtrail_fields = match schema.field(2).data_type() {
            DataType::Struct(fields) => fields.clone(),
            _ => Fields::empty(),
        };
        Self {
            schema,
            envelope: StructBuilder::from_fields(envelope_fields, capacity),
            payload_json: StringBuilder::with_capacity(capacity, capacity * 128),
            cloudtrail: StructBuilder::from_fields(cloudtrail_fields, capacity),
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn append_event(
        &mut self,
        event: &Event,
        payload_json: Option<&str>,
    ) -> Result<(), arrow_schema::ArrowError> {
        self.append_envelope(&event.envelope);
        match payload_json {
            Some(value) => self.payload_json.append_value(value),
            None => self.payload_json.append_null(),
        }
        append_cloudtrail(&mut self.cloudtrail, event);
        self.len += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<RecordBatch, arrow_schema::ArrowError> {
        let envelope_array: ArrayRef = Arc::new(self.envelope.finish());
        let payload_array: ArrayRef = Arc::new(self.payload_json.finish());
        let cloudtrail_array: ArrayRef = Arc::new(self.cloudtrail.finish());
        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![envelope_array, payload_array, cloudtrail_array],
        )?;
        self.len = 0;
        Ok(batch)
    }

    fn append_envelope(&mut self, envelope: &crate::core::event::EventEnvelope) {
        let builder = &mut self.envelope;

        append_string(builder.field_builder::<StringBuilder>(0).unwrap(), Some(&envelope.schema_version));
        append_string(builder.field_builder::<StringBuilder>(1).unwrap(), Some(&envelope.timestamp));
        append_string(builder.field_builder::<StringBuilder>(2).unwrap(), Some(&envelope.source));
        append_string(builder.field_builder::<StringBuilder>(3).unwrap(), Some(&envelope.event_type));

        let actor_builder = builder.field_builder::<StructBuilder>(4).unwrap();
        append_actor(actor_builder, &envelope.actor);

        let target_builder = builder.field_builder::<StructBuilder>(5).unwrap();
        append_target(target_builder, envelope.target.as_ref());

        append_string(
            builder.field_builder::<StringBuilder>(6).unwrap(),
            Some(outcome_to_str(&envelope.outcome)),
        );

        let geo_builder = builder.field_builder::<StructBuilder>(7).unwrap();
        append_geo(geo_builder, envelope.geo.as_ref());

        append_string(builder.field_builder::<StringBuilder>(8).unwrap(), envelope.ip.as_deref());
        append_string(
            builder.field_builder::<StringBuilder>(9).unwrap(),
            envelope.user_agent.as_deref(),
        );
        append_string(
            builder.field_builder::<StringBuilder>(10).unwrap(),
            envelope.session_id.as_deref(),
        );
        append_string(
            builder.field_builder::<StringBuilder>(11).unwrap(),
            envelope.tenant_id.as_deref(),
        );

        builder.append(true);
    }
}

fn build_schema() -> SchemaRef {
    let actor_fields = Fields::from(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("kind", DataType::Utf8, false),
        Field::new("name", DataType::Utf8, true),
    ]);

    let target_fields = Fields::from(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("kind", DataType::Utf8, false),
        Field::new("name", DataType::Utf8, true),
    ]);

    let geo_fields = Fields::from(vec![
        Field::new("country", DataType::Utf8, false),
        Field::new("region", DataType::Utf8, true),
        Field::new("city", DataType::Utf8, true),
        Field::new("lat", DataType::Float64, true),
        Field::new("lon", DataType::Float64, true),
    ]);

    let envelope_fields = Fields::from(vec![
        Field::new("schema_version", DataType::Utf8, false),
        Field::new("timestamp", DataType::Utf8, false),
        Field::new("source", DataType::Utf8, false),
        Field::new("event_type", DataType::Utf8, false),
        Field::new("actor", DataType::Struct(actor_fields), false),
        Field::new("target", DataType::Struct(target_fields), true),
        Field::new("outcome", DataType::Utf8, false),
        Field::new("geo", DataType::Struct(geo_fields), true),
        Field::new("ip", DataType::Utf8, true),
        Field::new("user_agent", DataType::Utf8, true),
        Field::new("session_id", DataType::Utf8, true),
        Field::new("tenant_id", DataType::Utf8, true),
    ]);

    let cloudtrail_identity_fields = Fields::from(vec![
        Field::new("type", DataType::Utf8, true),
        Field::new("principalId", DataType::Utf8, true),
        Field::new("arn", DataType::Utf8, true),
        Field::new("accountId", DataType::Utf8, true),
        Field::new("accessKeyId", DataType::Utf8, true),
        Field::new("userName", DataType::Utf8, true),
    ]);

    let cloudtrail_fields = Fields::from(vec![
        Field::new("eventVersion", DataType::Utf8, true),
        Field::new("eventTime", DataType::Utf8, true),
        Field::new("eventSource", DataType::Utf8, true),
        Field::new("eventName", DataType::Utf8, true),
        Field::new("awsRegion", DataType::Utf8, true),
        Field::new("sourceIPAddress", DataType::Utf8, true),
        Field::new("userAgent", DataType::Utf8, true),
        Field::new(
            "userIdentity",
            DataType::Struct(cloudtrail_identity_fields),
            true,
        ),
        Field::new("requestParametersJson", DataType::Utf8, true),
        Field::new("responseElementsJson", DataType::Utf8, true),
        Field::new("errorCode", DataType::Utf8, true),
        Field::new("errorMessage", DataType::Utf8, true),
        Field::new("requestID", DataType::Utf8, true),
        Field::new("eventID", DataType::Utf8, true),
        Field::new("readOnly", DataType::Boolean, true),
        Field::new("eventType", DataType::Utf8, true),
        Field::new("managementEvent", DataType::Boolean, true),
        Field::new("recipientAccountId", DataType::Utf8, true),
        Field::new("eventCategory", DataType::Utf8, true),
        Field::new("tlsDetailsJson", DataType::Utf8, true),
        Field::new("sessionCredentialFromConsole", DataType::Boolean, true),
    ]);

    let fields = vec![
        Field::new("envelope", DataType::Struct(envelope_fields), false),
        Field::new("payload_json", DataType::Utf8, true),
        Field::new("cloudtrail", DataType::Struct(cloudtrail_fields), true),
    ];

    Arc::new(Schema::new(fields))
}

fn build_file_path(
    dir: &Path,
    account_id: &str,
    region: &str,
    stamp: &str,
    unique: &str,
    ext: &str,
    prefix: Option<&str>,
) -> PathBuf {
    let name = match prefix {
        Some(prefix) if !prefix.trim().is_empty() => {
            format!("{prefix}_{account_id}_{region}_{stamp}_{unique}.{ext}")
        }
        _ => format!("{account_id}_CloudTrail_{region}_{stamp}_{unique}.{ext}"),
    };
    dir.join(name)
}

fn open_writer(
    dir: &Path,
    account_id: &str,
    region: &str,
    stamp: &str,
    unique: &str,
    ext: &str,
    schema: SchemaRef,
    prefix: Option<&str>,
) -> io::Result<(ArrowWriter<File>, PathBuf)> {
    let path = build_file_path(dir, account_id, region, stamp, unique, ext, prefix);
    let file = File::create(&path)?;
    let props = WriterProperties::builder().build();
    let writer = ArrowWriter::try_new(file, schema, Some(props)).map_err(map_parquet_err)?;
    Ok((writer, path))
}

fn append_actor(builder: &mut StructBuilder, actor: &Actor) {
    append_string(builder.field_builder::<StringBuilder>(0).unwrap(), Some(&actor.id));
    append_string(builder.field_builder::<StringBuilder>(1).unwrap(), Some(&actor.kind));
    append_string(
        builder.field_builder::<StringBuilder>(2).unwrap(),
        actor.name.as_deref(),
    );
    builder.append(true);
}

fn append_target(builder: &mut StructBuilder, target: Option<&Target>) {
    match target {
        Some(target) => {
            append_string(builder.field_builder::<StringBuilder>(0).unwrap(), Some(&target.id));
            append_string(builder.field_builder::<StringBuilder>(1).unwrap(), Some(&target.kind));
            append_string(
                builder.field_builder::<StringBuilder>(2).unwrap(),
                target.name.as_deref(),
            );
            builder.append(true);
        }
        None => {
            append_string(builder.field_builder::<StringBuilder>(0).unwrap(), None);
            append_string(builder.field_builder::<StringBuilder>(1).unwrap(), None);
            append_string(builder.field_builder::<StringBuilder>(2).unwrap(), None);
            builder.append(false);
        }
    }
}

fn append_geo(builder: &mut StructBuilder, geo: Option<&Geo>) {
    match geo {
        Some(geo) => {
            append_string(builder.field_builder::<StringBuilder>(0).unwrap(), Some(&geo.country));
            append_string(
                builder.field_builder::<StringBuilder>(1).unwrap(),
                geo.region.as_deref(),
            );
            append_string(
                builder.field_builder::<StringBuilder>(2).unwrap(),
                geo.city.as_deref(),
            );
            append_float(builder.field_builder::<Float64Builder>(3).unwrap(), geo.lat);
            append_float(builder.field_builder::<Float64Builder>(4).unwrap(), geo.lon);
            builder.append(true);
        }
        None => {
            append_string(builder.field_builder::<StringBuilder>(0).unwrap(), None);
            append_string(builder.field_builder::<StringBuilder>(1).unwrap(), None);
            append_string(builder.field_builder::<StringBuilder>(2).unwrap(), None);
            append_float(builder.field_builder::<Float64Builder>(3).unwrap(), None);
            append_float(builder.field_builder::<Float64Builder>(4).unwrap(), None);
            builder.append(false);
        }
    }
}

fn append_string(builder: &mut StringBuilder, value: Option<&str>) {
    match value {
        Some(value) => builder.append_value(value),
        None => builder.append_null(),
    }
}

fn append_bool(builder: &mut BooleanBuilder, value: Option<bool>) {
    match value {
        Some(value) => builder.append_value(value),
        None => builder.append_null(),
    }
}

fn append_float(builder: &mut Float64Builder, value: Option<f64>) {
    match value {
        Some(value) => builder.append_value(value),
        None => builder.append_null(),
    }
}

fn outcome_to_str(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Success => "success",
        Outcome::Failure => "failure",
        Outcome::Unknown => "unknown",
    }
}

fn append_cloudtrail(builder: &mut StructBuilder, event: &Event) {
    if event.envelope.source != "cloudtrail" {
        append_cloudtrail_null(builder);
        return;
    }

    let payload = match event.payload.as_object() {
        Some(payload) => payload,
        None => {
            append_cloudtrail_null(builder);
            return;
        }
    };

    let get_str = |primary: &str, fallback: &str| -> Option<&str> {
        payload
            .get(primary)
            .and_then(Value::as_str)
            .or_else(|| payload.get(fallback).and_then(Value::as_str))
    };
    let get_bool = |primary: &str, fallback: &str| -> Option<bool> {
        payload
            .get(primary)
            .and_then(Value::as_bool)
            .or_else(|| payload.get(fallback).and_then(Value::as_bool))
    };

    append_string(
        builder.field_builder::<StringBuilder>(0).unwrap(),
        get_str("eventVersion", "event_version"),
    );
    append_string(
        builder.field_builder::<StringBuilder>(1).unwrap(),
        get_str("eventTime", "event_time"),
    );
    append_string(
        builder.field_builder::<StringBuilder>(2).unwrap(),
        get_str("eventSource", "event_source"),
    );
    append_string(
        builder.field_builder::<StringBuilder>(3).unwrap(),
        get_str("eventName", "event_name"),
    );
    append_string(
        builder.field_builder::<StringBuilder>(4).unwrap(),
        get_str("awsRegion", "aws_region"),
    );
    append_string(
        builder.field_builder::<StringBuilder>(5).unwrap(),
        get_str("sourceIPAddress", "source_ip_address"),
    );
    append_string(
        builder.field_builder::<StringBuilder>(6).unwrap(),
        get_str("userAgent", "user_agent"),
    );

    let identity_builder = builder.field_builder::<StructBuilder>(7).unwrap();
    append_cloudtrail_identity(
        identity_builder,
        payload
            .get("userIdentity")
            .or_else(|| payload.get("user_identity")),
    );

    let request_json = payload
        .get("requestParameters")
        .or_else(|| payload.get("request_parameters"))
        .and_then(|value| serde_json::to_string(value).ok());
    append_string(
        builder.field_builder::<StringBuilder>(8).unwrap(),
        request_json.as_deref(),
    );

    let response_json = payload
        .get("responseElements")
        .or_else(|| payload.get("response_elements"))
        .and_then(|value| serde_json::to_string(value).ok());
    append_string(
        builder.field_builder::<StringBuilder>(9).unwrap(),
        response_json.as_deref(),
    );

    append_string(
        builder.field_builder::<StringBuilder>(10).unwrap(),
        get_str("errorCode", "error_code"),
    );
    append_string(
        builder.field_builder::<StringBuilder>(11).unwrap(),
        get_str("errorMessage", "error_message"),
    );
    append_string(
        builder.field_builder::<StringBuilder>(12).unwrap(),
        get_str("requestID", "request_id"),
    );
    append_string(
        builder.field_builder::<StringBuilder>(13).unwrap(),
        get_str("eventID", "event_id"),
    );
    append_bool(
        builder.field_builder::<BooleanBuilder>(14).unwrap(),
        get_bool("readOnly", "read_only"),
    );
    append_string(
        builder.field_builder::<StringBuilder>(15).unwrap(),
        get_str("eventType", "event_type"),
    );
    append_bool(
        builder.field_builder::<BooleanBuilder>(16).unwrap(),
        get_bool("managementEvent", "management_event"),
    );
    append_string(
        builder.field_builder::<StringBuilder>(17).unwrap(),
        get_str("recipientAccountId", "recipient_account_id"),
    );
    append_string(
        builder.field_builder::<StringBuilder>(18).unwrap(),
        get_str("eventCategory", "event_category"),
    );
    let tls_json = payload
        .get("tlsDetails")
        .or_else(|| payload.get("tls_details"))
        .and_then(|value| serde_json::to_string(value).ok());
    append_string(
        builder.field_builder::<StringBuilder>(19).unwrap(),
        tls_json.as_deref(),
    );
    append_bool(
        builder.field_builder::<BooleanBuilder>(20).unwrap(),
        get_bool(
            "sessionCredentialFromConsole",
            "session_credential_from_console",
        ),
    );

    builder.append(true);
}

fn append_cloudtrail_identity(builder: &mut StructBuilder, value: Option<&Value>) {
    if let Some(map) = value.and_then(Value::as_object) {
        let get_str = |primary: &str, fallback: &str| -> Option<&str> {
            map.get(primary)
                .and_then(Value::as_str)
                .or_else(|| map.get(fallback).and_then(Value::as_str))
        };
        append_string(
            builder.field_builder::<StringBuilder>(0).unwrap(),
            get_str("type", "identity_type"),
        );
        append_string(
            builder.field_builder::<StringBuilder>(1).unwrap(),
            get_str("principalId", "principal_id"),
        );
        append_string(
            builder.field_builder::<StringBuilder>(2).unwrap(),
            get_str("arn", "arn"),
        );
        append_string(
            builder.field_builder::<StringBuilder>(3).unwrap(),
            get_str("accountId", "account_id"),
        );
        append_string(
            builder.field_builder::<StringBuilder>(4).unwrap(),
            get_str("accessKeyId", "access_key_id"),
        );
        append_string(
            builder.field_builder::<StringBuilder>(5).unwrap(),
            get_str("userName", "user_name"),
        );
        builder.append(true);
    } else {
        append_cloudtrail_identity_null(builder);
    }
}

fn append_cloudtrail_null(builder: &mut StructBuilder) {
    append_string(builder.field_builder::<StringBuilder>(0).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(1).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(2).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(3).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(4).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(5).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(6).unwrap(), None);

    let identity_builder = builder.field_builder::<StructBuilder>(7).unwrap();
    append_cloudtrail_identity_null(identity_builder);

    append_string(builder.field_builder::<StringBuilder>(8).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(9).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(10).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(11).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(12).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(13).unwrap(), None);
    append_bool(builder.field_builder::<BooleanBuilder>(14).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(15).unwrap(), None);
    append_bool(builder.field_builder::<BooleanBuilder>(16).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(17).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(18).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(19).unwrap(), None);
    append_bool(builder.field_builder::<BooleanBuilder>(20).unwrap(), None);

    builder.append(false);
}

fn append_cloudtrail_identity_null(builder: &mut StructBuilder) {
    append_string(builder.field_builder::<StringBuilder>(0).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(1).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(2).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(3).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(4).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(5).unwrap(), None);
    builder.append(false);
}

fn estimate_event_size(event: &Event, payload_json: Option<&str>) -> u64 {
    let envelope = &event.envelope;
    let mut size = 0usize;

    size += envelope.schema_version.len();
    size += envelope.timestamp.len();
    size += envelope.source.len();
    size += envelope.event_type.len();
    size += envelope.actor.id.len();
    size += envelope.actor.kind.len();
    if let Some(name) = &envelope.actor.name {
        size += name.len();
    }
    if let Some(target) = &envelope.target {
        size += target.id.len();
        size += target.kind.len();
        if let Some(name) = &target.name {
            size += name.len();
        }
    }
    if let Some(geo) = &envelope.geo {
        size += geo.country.len();
        if let Some(region) = &geo.region {
            size += region.len();
        }
        if let Some(city) = &geo.city {
            size += city.len();
        }
    }
    if let Some(ip) = &envelope.ip {
        size += ip.len();
    }
    if let Some(user_agent) = &envelope.user_agent {
        size += user_agent.len();
    }
    if let Some(session_id) = &envelope.session_id {
        size += session_id.len();
    }
    if let Some(tenant_id) = &envelope.tenant_id {
        size += tenant_id.len();
    }
    if let Some(payload) = payload_json {
        size += payload.len();
    }

    size as u64
}

fn map_parquet_err(err: ParquetError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

fn map_arrow_err(err: arrow_schema::ArrowError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
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

struct FileContext {
    account_id: String,
    region: String,
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

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct RegionKey {
    account_id: String,
    region: String,
}

struct RegionState {
    current_size: u64,
    batch: EventBatchBuilder,
    first_event_at: Option<Instant>,
}

impl RegionState {
    fn new(schema: SchemaRef, batch_size: usize) -> Self {
        Self {
            current_size: 0,
            batch: EventBatchBuilder::new(schema, batch_size),
            first_event_at: None,
        }
    }
}

fn flush_region(
    dir: &Path,
    schema: &SchemaRef,
    prefix: Option<&str>,
    key: &RegionKey,
    state: &mut RegionState,
) -> io::Result<()> {
    if state.batch.len() == 0 {
        return Ok(());
    }

    let batch = state.batch.finish().map_err(map_arrow_err)?;
    let stamp = current_stamp();
    let unique = unique_id();
    let (mut writer, temp_path) = open_writer(
        dir,
        &key.account_id,
        &key.region,
        &stamp,
        &unique,
        "parquet.tmp",
        schema.clone(),
        prefix,
    )?;
    writer.write(&batch).map_err(map_parquet_err)?;
    writer.close().map_err(map_parquet_err)?;
    let final_path = build_file_path(
        dir,
        &key.account_id,
        &key.region,
        &stamp,
        &unique,
        "parquet",
        prefix,
    );
    fs::rename(&temp_path, &final_path)?;
    state.current_size = 0;
    state.first_event_at = None;
    Ok(())
}
