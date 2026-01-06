//! Parquet persistence for actor populations.
//!
//! Stores `ActorSeed` data so sources can reuse a shared population.

use arrow_array::builder::{
    BooleanBuilder, Float64Builder, Int16Builder, Int8Builder, StringBuilder,
};
use arrow_array::{
    Array, BooleanArray, Float64Array, Int16Array, Int8Array, RecordBatch, StringArray,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::arrow_writer::ArrowWriter;
use parquet::errors::ParquetError;
use parquet::file::properties::WriterProperties;
use crate::core::actors::{
    ActorKind, ActorPopulation, ActorRole, ActorSeed, RoleRates, ServicePattern, ServiceProfile,
};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::Path;
use std::sync::Arc;

/// Writes an actor population to a Parquet file.
pub fn write_population(path: impl AsRef<Path>, population: &ActorPopulation) -> io::Result<()> {
    let schema = build_schema();
    let mut kind_builder = StringBuilder::new();
    let mut role_builder = StringBuilder::new();
    let mut identity_type_builder = StringBuilder::new();
    let mut principal_id_builder = StringBuilder::new();
    let mut arn_builder = StringBuilder::new();
    let mut account_id_builder = StringBuilder::new();
    let mut user_name_builder = StringBuilder::new();
    let mut user_agent_builder = StringBuilder::new();
    let mut source_ip_builder = StringBuilder::new();
    let mut active_start_builder = Int16Builder::new();
    let mut active_hours_builder = Int16Builder::new();
    let mut timezone_offset_builder = Int8Builder::new();
    let mut weekend_active_builder = BooleanBuilder::new();
    let mut access_key_id_builder = StringBuilder::new();
    let mut rate_per_hour_builder = Float64Builder::new();
    let mut service_profile_builder = StringBuilder::new();
    let mut service_pattern_builder = StringBuilder::new();
    let mut error_rate_builder = Float64Builder::new();
    let mut actor_id_builder = StringBuilder::new();
    let mut tags_builder = StringBuilder::new();
    let mut event_bias_builder = StringBuilder::new();

    for actor in &population.actors {
        kind_builder.append_value(kind_to_str(&actor.kind));
        if let Some(role) = &actor.role {
            role_builder.append_value(role_to_str(role));
        } else {
            role_builder.append_null();
        }
        identity_type_builder.append_value(&actor.identity_type);
        principal_id_builder.append_value(&actor.principal_id);
        arn_builder.append_value(&actor.arn);
        account_id_builder.append_value(&actor.account_id);
        access_key_id_builder.append_value(&actor.access_key_id);
        if let Some(name) = &actor.user_name {
            user_name_builder.append_value(name);
        } else {
            user_name_builder.append_null();
        }
        user_agent_builder.append_value(encode_string_list(&actor.user_agents));
        source_ip_builder.append_value(encode_string_list(&actor.source_ips));
        active_start_builder.append_value(actor.active_start_hour as i16);
        active_hours_builder.append_value(actor.active_hours as i16);
        timezone_offset_builder.append_value(actor.timezone_offset);
        weekend_active_builder.append_value(actor.weekend_active);
        rate_per_hour_builder.append_value(actor.rate_per_hour);
        if let Some(profile) = &actor.service_profile {
            service_profile_builder.append_value(service_profile_to_str(profile));
        } else {
            service_profile_builder.append_null();
        }
        if let Some(pattern) = &actor.service_pattern {
            service_pattern_builder.append_value(service_pattern_to_str(pattern));
        } else {
            service_pattern_builder.append_null();
        }
        error_rate_builder.append_value(actor.error_rate);
        if let Some(id) = &actor.id {
            actor_id_builder.append_value(id);
        } else {
            actor_id_builder.append_null();
        }
        if actor.tags.is_empty() {
            tags_builder.append_null();
        } else {
            tags_builder.append_value(encode_string_list(&actor.tags));
        }
        if actor.event_bias.is_empty() {
            event_bias_builder.append_null();
        } else {
            event_bias_builder.append_value(encode_event_bias(&actor.event_bias));
        }
    }

    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(kind_builder.finish()),
            Arc::new(role_builder.finish()),
            Arc::new(identity_type_builder.finish()),
            Arc::new(principal_id_builder.finish()),
            Arc::new(arn_builder.finish()),
            Arc::new(account_id_builder.finish()),
            Arc::new(user_name_builder.finish()),
            Arc::new(user_agent_builder.finish()),
            Arc::new(source_ip_builder.finish()),
            Arc::new(active_start_builder.finish()),
            Arc::new(active_hours_builder.finish()),
            Arc::new(timezone_offset_builder.finish()),
            Arc::new(weekend_active_builder.finish()),
            Arc::new(access_key_id_builder.finish()),
            Arc::new(rate_per_hour_builder.finish()),
            Arc::new(service_profile_builder.finish()),
            Arc::new(service_pattern_builder.finish()),
            Arc::new(error_rate_builder.finish()),
            Arc::new(actor_id_builder.finish()),
            Arc::new(tags_builder.finish()),
            Arc::new(event_bias_builder.finish()),
        ],
    )
    .map_err(map_arrow_err)?;

    let file = File::create(path)?;
    let props = WriterProperties::builder().build();
    let mut writer =
        ArrowWriter::try_new(file, schema, Some(props)).map_err(map_parquet_err)?;
    writer.write(&batch).map_err(map_parquet_err)?;
    writer.close().map_err(map_parquet_err)?;
    Ok(())
}

/// Reads an actor population from a Parquet file.
pub fn read_population(path: impl AsRef<Path>) -> io::Result<ActorPopulation> {
    let file = File::open(path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).map_err(map_parquet_err)?;
    let mut reader = builder.build().map_err(map_parquet_err)?;
    let mut actors = Vec::new();

    while let Some(batch) = reader.next() {
        let batch = batch.map_err(map_arrow_err)?;
        actors.extend(read_batch(&batch)?);
    }

    Ok(ActorPopulation { actors })
}

fn read_batch(batch: &RecordBatch) -> io::Result<Vec<ActorSeed>> {
    let kind = column_as_string_required(batch, 0)?;
    let role = column_as_string_optional(batch, 1)?;
    let identity_type = column_as_string_required(batch, 2)?;
    let principal_id = column_as_string_required(batch, 3)?;
    let arn = column_as_string_required(batch, 4)?;
    let account_id = column_as_string_required(batch, 5)?;
    let user_name = column_as_string_optional(batch, 6)?;
    let user_agent = column_as_string_required(batch, 7)?;
    let source_ip = column_as_string_required(batch, 8)?;
    let active_start = column_as_i16(batch, 9)?;
    let active_hours = column_as_i16(batch, 10)?;
    let timezone_offset = column_as_i8(batch, 11)?;
    let weekend_active = column_as_bool(batch, 12)?;
    let access_key_id = column_as_string_optional_fallback(batch, 13)?;
    let rate_per_hour = column_as_f64_optional_fallback(batch, 14)?;
    let service_profile = column_as_string_optional_fallback(batch, 15)?;
    let service_pattern = column_as_string_optional_fallback(batch, 16)?;
    let error_rate = column_as_f64_optional_fallback(batch, 17)?;
    let actor_id = column_as_string_optional_fallback(batch, 18)?;
    let tags = column_as_string_optional_fallback(batch, 19)?;
    let event_bias = column_as_string_optional_fallback(batch, 20)?;

    let mut actors = Vec::with_capacity(batch.num_rows());
    for idx in 0..batch.num_rows() {
        let kind = parse_kind(&kind[idx])?;
        let role = match role.get(idx).and_then(|value| value.as_deref()) {
            Some(value) => Some(parse_role(value)?),
            None => None,
        };

        let parsed_profile = service_profile
            .get(idx)
            .and_then(|value| value.as_deref())
            .and_then(parse_service_profile);
        let parsed_pattern = service_pattern
            .get(idx)
            .and_then(|value| value.as_deref())
            .and_then(parse_service_pattern);
        let resolved_profile = match kind {
            ActorKind::Service => parsed_profile.or(Some(ServiceProfile::Generic)),
            ActorKind::Human => None,
        };
        let resolved_pattern = match kind {
            ActorKind::Service => parsed_pattern.or(Some(ServicePattern::Constant)),
            ActorKind::Human => None,
        };
        let mut resolved_rate = rate_per_hour
            .get(idx)
            .and_then(|value| *value)
            .unwrap_or_else(|| fallback_rate_per_hour(&kind, role.as_ref()));
        if !resolved_rate.is_finite() || resolved_rate <= 0.0 {
            resolved_rate = fallback_rate_per_hour(&kind, role.as_ref());
        }
        let mut resolved_error_rate = error_rate
            .get(idx)
            .and_then(|value| *value)
            .unwrap_or_else(|| fallback_error_rate(&kind));
        if !resolved_error_rate.is_finite() || resolved_error_rate < 0.0 {
            resolved_error_rate = fallback_error_rate(&kind);
        }
        let tags = tags
            .get(idx)
            .and_then(|value| value.as_deref())
            .map(parse_optional_string_list)
            .unwrap_or_default();
        let event_bias = event_bias
            .get(idx)
            .and_then(|value| value.as_deref())
            .map(parse_event_bias)
            .unwrap_or_default();

        let seed = ActorSeed {
            kind,
            role,
            id: actor_id.get(idx).and_then(|value| value.clone()),
            identity_type: identity_type[idx].clone(),
            principal_id: principal_id[idx].clone(),
            arn: arn[idx].clone(),
            account_id: account_id[idx].clone(),
            access_key_id: access_key_id
                .get(idx)
                .and_then(|value| value.clone())
                .unwrap_or_else(|| fallback_access_key_id(&identity_type[idx], &principal_id[idx])),
            rate_per_hour: resolved_rate,
            error_rate: resolved_error_rate,
            tags,
            event_bias,
            service_profile: resolved_profile,
            service_pattern: resolved_pattern,
            user_name: user_name.get(idx).cloned().flatten(),
            user_agents: parse_string_list(&user_agent[idx], "user_agent")?,
            source_ips: parse_string_list(&source_ip[idx], "source_ip")?,
            active_start_hour: i16_to_u8(active_start[idx], "active_start_hour")?,
            active_hours: i16_to_u8(active_hours[idx], "active_hours")?,
            timezone_offset: timezone_offset[idx],
            timezone_fixed: false,
            weekend_active: weekend_active[idx],
        };
        actors.push(seed);
    }

    Ok(actors)
}

fn build_schema() -> SchemaRef {
    let fields = vec![
        Field::new("actor_kind", DataType::Utf8, false),
        Field::new("role", DataType::Utf8, true),
        Field::new("identity_type", DataType::Utf8, false),
        Field::new("principal_id", DataType::Utf8, false),
        Field::new("arn", DataType::Utf8, false),
        Field::new("account_id", DataType::Utf8, false),
        Field::new("user_name", DataType::Utf8, true),
        Field::new("user_agent", DataType::Utf8, false),
        Field::new("source_ip", DataType::Utf8, false),
        Field::new("active_start_hour", DataType::Int16, false),
        Field::new("active_hours", DataType::Int16, false),
        Field::new("timezone_offset", DataType::Int8, false),
        Field::new("weekend_active", DataType::Boolean, false),
        Field::new("access_key_id", DataType::Utf8, false),
        Field::new("rate_per_hour", DataType::Float64, false),
        Field::new("service_profile", DataType::Utf8, true),
        Field::new("service_pattern", DataType::Utf8, true),
        Field::new("error_rate", DataType::Float64, false),
        Field::new("actor_id", DataType::Utf8, true),
        Field::new("tags", DataType::Utf8, true),
        Field::new("event_bias", DataType::Utf8, true),
    ];

    Arc::new(Schema::new(fields))
}

fn kind_to_str(kind: &ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Service => "service",
    }
}

fn role_to_str(role: &ActorRole) -> &'static str {
    match role {
        ActorRole::Admin => "admin",
        ActorRole::Developer => "developer",
        ActorRole::ReadOnly => "readonly",
        ActorRole::Auditor => "auditor",
    }
}

fn parse_kind(value: &str) -> io::Result<ActorKind> {
    match value {
        "human" => Ok(ActorKind::Human),
        "service" => Ok(ActorKind::Service),
        other => Err(invalid_data(format!("unknown actor_kind: {other}"))),
    }
}

fn parse_role(value: &str) -> io::Result<ActorRole> {
    match value {
        "admin" => Ok(ActorRole::Admin),
        "developer" => Ok(ActorRole::Developer),
        "readonly" => Ok(ActorRole::ReadOnly),
        "auditor" => Ok(ActorRole::Auditor),
        other => Err(invalid_data(format!("unknown role: {other}"))),
    }
}

fn service_profile_to_str(profile: &ServiceProfile) -> &'static str {
    match profile {
        ServiceProfile::Generic => "generic",
        ServiceProfile::Ec2Reaper => "ec2_reaper",
        ServiceProfile::DataLakeBot => "datalake_bot",
        ServiceProfile::LogsShipper => "logs_shipper",
        ServiceProfile::MetricsCollector => "metrics_collector",
    }
}

fn service_pattern_to_str(pattern: &ServicePattern) -> &'static str {
    match pattern {
        ServicePattern::Constant => "constant",
        ServicePattern::Diurnal => "diurnal",
        ServicePattern::Bursty => "bursty",
    }
}

fn parse_service_profile(value: &str) -> Option<ServiceProfile> {
    match value.trim().to_lowercase().replace('-', "_").as_str() {
        "generic" => Some(ServiceProfile::Generic),
        "ec2_reaper" => Some(ServiceProfile::Ec2Reaper),
        "datalake_bot" => Some(ServiceProfile::DataLakeBot),
        "logs_shipper" => Some(ServiceProfile::LogsShipper),
        "metrics_collector" => Some(ServiceProfile::MetricsCollector),
        _ => None,
    }
}

fn parse_service_pattern(value: &str) -> Option<ServicePattern> {
    match value.trim().to_lowercase().as_str() {
        "constant" => Some(ServicePattern::Constant),
        "diurnal" => Some(ServicePattern::Diurnal),
        "bursty" => Some(ServicePattern::Bursty),
        _ => None,
    }
}

fn encode_string_list(values: &[String]) -> String {
    serde_json::to_string(values).unwrap_or_else(|_| "[]".to_string())
}

fn encode_event_bias(values: &HashMap<String, f64>) -> String {
    serde_json::to_string(values).unwrap_or_else(|_| "{}".to_string())
}

fn parse_string_list(value: &str, field: &str) -> io::Result<Vec<String>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid_data(format!("missing {field}")));
    }

    if trimmed.starts_with('[') {
        match serde_json::from_str::<Value>(trimmed) {
            Ok(Value::Array(items)) => {
                let mut values = Vec::new();
                for item in items {
                    if let Value::String(value) = item {
                        values.push(value);
                    }
                }
                if values.is_empty() {
                    return Err(invalid_data(format!("empty {field} list")));
                }
                return Ok(values);
            }
            _ => {
                return Ok(vec![trimmed.to_string()]);
            }
        }
    }

    Ok(vec![trimmed.to_string()])
}

fn parse_optional_string_list(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with('[') {
        if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(trimmed) {
            return items
                .into_iter()
                .filter_map(|item| {
                    if let Value::String(value) = item {
                        let trimmed = value.trim().to_string();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed)
                        }
                    } else {
                        None
                    }
                })
                .collect();
        }
    }
    vec![trimmed.to_string()]
}

fn parse_event_bias(value: &str) -> HashMap<String, f64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return HashMap::new();
    }
    let parsed = serde_json::from_str::<Value>(trimmed).ok();
    let Some(Value::Object(map)) = parsed else {
        return HashMap::new();
    };
    let mut bias = HashMap::new();
    for (key, value) in map {
        let Some(weight) = value.as_f64() else {
            continue;
        };
        if !weight.is_finite() || weight <= 0.0 {
            continue;
        }
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        bias.insert(key.to_string(), weight);
    }
    bias
}

fn column_as_string_optional_fallback(
    batch: &RecordBatch,
    index: usize,
) -> io::Result<Vec<Option<String>>> {
    if index >= batch.num_columns() {
        return Ok(vec![None; batch.num_rows()]);
    }
    column_as_string_optional(batch, index)
}

fn fallback_access_key_id(identity_type: &str, seed: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut hasher);
    let prefix = if identity_type == "AssumedRole" { "ASIA" } else { "AKIA" };
    format!("{prefix}{:016X}", hasher.finish())
}

fn fallback_rate_per_hour(kind: &ActorKind, role: Option<&ActorRole>) -> f64 {
    match kind {
        ActorKind::Human => {
            let rates = RoleRates::default();
            let role = role.unwrap_or(&ActorRole::Developer);
            rates.for_role(role)
        }
        ActorKind::Service => 6.0,
    }
}

fn fallback_error_rate(kind: &ActorKind) -> f64 {
    match kind {
        ActorKind::Human => 0.03,
        ActorKind::Service => 0.01,
    }
}

fn column_as_f64_optional_fallback(
    batch: &RecordBatch,
    index: usize,
) -> io::Result<Vec<Option<f64>>> {
    if index >= batch.num_columns() {
        return Ok(vec![None; batch.num_rows()]);
    }
    column_as_f64_optional(batch, index)
}

fn column_as_f64_optional(batch: &RecordBatch, index: usize) -> io::Result<Vec<Option<f64>>> {
    let array = batch
        .column(index)
        .as_any()
        .downcast_ref::<Float64Array>()
        .ok_or_else(|| invalid_data(format!("column {index} is not Float64")))?;
    let mut values = Vec::with_capacity(array.len());
    for idx in 0..array.len() {
        if array.is_null(idx) {
            values.push(None);
        } else {
            values.push(Some(array.value(idx)));
        }
    }
    Ok(values)
}

fn column_as_string_required(batch: &RecordBatch, index: usize) -> io::Result<Vec<String>> {
    let array = batch
        .column(index)
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| invalid_data(format!("column {index} is not Utf8")))?;
    let mut values = Vec::with_capacity(array.len());
    for idx in 0..array.len() {
        if array.is_null(idx) {
            return Err(invalid_data(format!("missing column {index} value")));
        }
        values.push(array.value(idx).to_string());
    }
    Ok(values)
}

fn column_as_string_optional(batch: &RecordBatch, index: usize) -> io::Result<Vec<Option<String>>> {
    let array = batch
        .column(index)
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| invalid_data(format!("column {index} is not Utf8")))?;
    let mut values = Vec::with_capacity(array.len());
    for idx in 0..array.len() {
        if array.is_null(idx) {
            values.push(None);
        } else {
            values.push(Some(array.value(idx).to_string()));
        }
    }
    Ok(values)
}

fn column_as_i16(batch: &RecordBatch, index: usize) -> io::Result<Vec<i16>> {
    let array = batch
        .column(index)
        .as_any()
        .downcast_ref::<Int16Array>()
        .ok_or_else(|| invalid_data(format!("column {index} is not Int16")))?;
    Ok((0..array.len()).map(|idx| array.value(idx)).collect())
}

fn column_as_i8(batch: &RecordBatch, index: usize) -> io::Result<Vec<i8>> {
    let array = batch
        .column(index)
        .as_any()
        .downcast_ref::<Int8Array>()
        .ok_or_else(|| invalid_data(format!("column {index} is not Int8")))?;
    Ok((0..array.len()).map(|idx| array.value(idx)).collect())
}

fn column_as_bool(batch: &RecordBatch, index: usize) -> io::Result<Vec<bool>> {
    let array = batch
        .column(index)
        .as_any()
        .downcast_ref::<BooleanArray>()
        .ok_or_else(|| invalid_data(format!("column {index} is not Boolean")))?;
    Ok((0..array.len()).map(|idx| array.value(idx)).collect())
}

fn i16_to_u8(value: i16, field: &str) -> io::Result<u8> {
    if value < 0 || value > u8::MAX as i16 {
        return Err(invalid_data(format!("invalid {field}: {value}")));
    }
    Ok(value as u8)
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn map_parquet_err(err: ParquetError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

fn map_arrow_err(err: arrow_schema::ArrowError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}
