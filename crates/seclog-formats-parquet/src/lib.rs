use arrow_array::builder::{BooleanBuilder, Float64Builder, StringBuilder, StructBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef};
use parquet::arrow::arrow_writer::ArrowWriter;
use parquet::errors::ParquetError;
use parquet::file::properties::WriterProperties;
use seclog_core::event::{Actor, Event, Geo, Outcome, Target};
use seclog_core::traits::EventWriter;
use serde_json::Value;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_BATCH_SIZE: usize = 1024;

pub struct ParquetWriter {
    dir: PathBuf,
    target_size_bytes: u64,
    current_size: u64,
    file_index: u64,
    writer: Option<ArrowWriter<File>>,
    batch: EventBatchBuilder,
    batch_size: usize,
}

impl ParquetWriter {
    pub fn new(dir: impl Into<PathBuf>, target_size_mb: u64) -> io::Result<Self> {
        Self::with_batch_size(dir, target_size_mb, DEFAULT_BATCH_SIZE)
    }

    pub fn with_batch_size(
        dir: impl Into<PathBuf>,
        target_size_mb: u64,
        batch_size: usize,
    ) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let schema = build_schema();
        let writer = open_writer(&dir, 1, schema.clone())?;
        Ok(Self {
            dir,
            target_size_bytes: target_size_mb.saturating_mul(1024 * 1024),
            current_size: 0,
            file_index: 1,
            writer: Some(writer),
            batch: EventBatchBuilder::new(schema, batch_size),
            batch_size,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.flush_batch()?;
        let writer = self.take_writer()?;
        writer.close().map_err(map_parquet_err)?;
        self.file_index += 1;
        let schema = self.batch.schema();
        self.writer = Some(open_writer(&self.dir, self.file_index, schema)?);
        self.current_size = 0;
        Ok(())
    }

    fn flush_batch(&mut self) -> io::Result<()> {
        if self.batch.len() == 0 {
            return Ok(());
        }

        let batch = self.batch.finish().map_err(map_arrow_err)?;
        let writer = self.writer.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "parquet writer not initialized")
        })?;
        writer.write(&batch).map_err(map_parquet_err)?;
        Ok(())
    }

    fn take_writer(&mut self) -> io::Result<ArrowWriter<File>> {
        self.writer
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "parquet writer not initialized"))
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
        if self.current_size > 0 && self.current_size + size > self.target_size_bytes {
            self.rotate()?;
        }

        self.batch
            .append_event(event, payload_json.as_deref())
            .map_err(map_arrow_err)?;
        self.current_size += size;

        if self.batch.len() >= self.batch_size {
            self.flush_batch()?;
        }

        Ok(size)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_batch()?;
        if let Some(writer) = self.writer.as_mut() {
            writer.flush().map_err(map_parquet_err)?;
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        self.flush()?;
        let writer = self.take_writer()?;
        writer.close().map_err(map_parquet_err)?;
        Ok(())
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

    fn schema(&self) -> SchemaRef {
        self.schema.clone()
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

    fn append_envelope(&mut self, envelope: &seclog_core::event::EventEnvelope) {
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
        Field::new("identity_type", DataType::Utf8, true),
        Field::new("principal_id", DataType::Utf8, true),
        Field::new("arn", DataType::Utf8, true),
        Field::new("account_id", DataType::Utf8, true),
        Field::new("user_name", DataType::Utf8, true),
    ]);

    let cloudtrail_fields = Fields::from(vec![
        Field::new("event_version", DataType::Utf8, true),
        Field::new("event_time", DataType::Utf8, true),
        Field::new("event_source", DataType::Utf8, true),
        Field::new("event_name", DataType::Utf8, true),
        Field::new("aws_region", DataType::Utf8, true),
        Field::new("source_ip_address", DataType::Utf8, true),
        Field::new("user_agent", DataType::Utf8, true),
        Field::new(
            "user_identity",
            DataType::Struct(cloudtrail_identity_fields),
            true,
        ),
        Field::new("request_parameters_json", DataType::Utf8, true),
        Field::new("response_elements_json", DataType::Utf8, true),
        Field::new("error_code", DataType::Utf8, true),
        Field::new("error_message", DataType::Utf8, true),
        Field::new("event_id", DataType::Utf8, true),
        Field::new("recipient_account_id", DataType::Utf8, true),
        Field::new("read_only", DataType::Boolean, true),
    ]);

    let fields = vec![
        Field::new("envelope", DataType::Struct(envelope_fields), false),
        Field::new("payload_json", DataType::Utf8, true),
        Field::new("cloudtrail", DataType::Struct(cloudtrail_fields), true),
    ];

    Arc::new(Schema::new(fields))
}

fn open_writer(dir: &Path, index: u64, schema: SchemaRef) -> io::Result<ArrowWriter<File>> {
    let path = dir.join(format!("events-{index:06}.parquet"));
    let file = File::create(path)?;
    let props = WriterProperties::builder().build();
    ArrowWriter::try_new(file, schema, Some(props)).map_err(map_parquet_err)
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

    append_string(
        builder.field_builder::<StringBuilder>(0).unwrap(),
        payload.get("event_version").and_then(Value::as_str),
    );
    append_string(
        builder.field_builder::<StringBuilder>(1).unwrap(),
        payload.get("event_time").and_then(Value::as_str),
    );
    append_string(
        builder.field_builder::<StringBuilder>(2).unwrap(),
        payload.get("event_source").and_then(Value::as_str),
    );
    append_string(
        builder.field_builder::<StringBuilder>(3).unwrap(),
        payload.get("event_name").and_then(Value::as_str),
    );
    append_string(
        builder.field_builder::<StringBuilder>(4).unwrap(),
        payload.get("aws_region").and_then(Value::as_str),
    );
    append_string(
        builder.field_builder::<StringBuilder>(5).unwrap(),
        payload.get("source_ip_address").and_then(Value::as_str),
    );
    append_string(
        builder.field_builder::<StringBuilder>(6).unwrap(),
        payload.get("user_agent").and_then(Value::as_str),
    );

    let identity_builder = builder.field_builder::<StructBuilder>(7).unwrap();
    append_cloudtrail_identity(identity_builder, payload.get("user_identity"));

    let request_json = payload
        .get("request_parameters")
        .and_then(|value| serde_json::to_string(value).ok());
    append_string(
        builder.field_builder::<StringBuilder>(8).unwrap(),
        request_json.as_deref(),
    );

    let response_json = payload
        .get("response_elements")
        .and_then(|value| serde_json::to_string(value).ok());
    append_string(
        builder.field_builder::<StringBuilder>(9).unwrap(),
        response_json.as_deref(),
    );

    append_string(
        builder.field_builder::<StringBuilder>(10).unwrap(),
        payload.get("error_code").and_then(Value::as_str),
    );
    append_string(
        builder.field_builder::<StringBuilder>(11).unwrap(),
        payload.get("error_message").and_then(Value::as_str),
    );
    append_string(
        builder.field_builder::<StringBuilder>(12).unwrap(),
        payload.get("event_id").and_then(Value::as_str),
    );
    append_string(
        builder.field_builder::<StringBuilder>(13).unwrap(),
        payload.get("recipient_account_id").and_then(Value::as_str),
    );
    append_bool(
        builder.field_builder::<BooleanBuilder>(14).unwrap(),
        payload.get("read_only").and_then(Value::as_bool),
    );

    builder.append(true);
}

fn append_cloudtrail_identity(builder: &mut StructBuilder, value: Option<&Value>) {
    if let Some(map) = value.and_then(Value::as_object) {
        append_string(
            builder.field_builder::<StringBuilder>(0).unwrap(),
            map.get("identity_type").and_then(Value::as_str),
        );
        append_string(
            builder.field_builder::<StringBuilder>(1).unwrap(),
            map.get("principal_id").and_then(Value::as_str),
        );
        append_string(
            builder.field_builder::<StringBuilder>(2).unwrap(),
            map.get("arn").and_then(Value::as_str),
        );
        append_string(
            builder.field_builder::<StringBuilder>(3).unwrap(),
            map.get("account_id").and_then(Value::as_str),
        );
        append_string(
            builder.field_builder::<StringBuilder>(4).unwrap(),
            map.get("user_name").and_then(Value::as_str),
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

    builder.append(false);
}

fn append_cloudtrail_identity_null(builder: &mut StructBuilder) {
    append_string(builder.field_builder::<StringBuilder>(0).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(1).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(2).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(3).unwrap(), None);
    append_string(builder.field_builder::<StringBuilder>(4).unwrap(), None);
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
