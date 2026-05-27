//! Databricks Zerobus output sink.
//!
//! Streams generated events to pre-created Unity Catalog Delta tables through
//! Zerobus Ingest. The writer keeps a separate stream and batch per source.

use crate::core::config::ZerobusOutputConfig;
use crate::core::event::{Event, Outcome};
use crate::core::traits::EventWriter;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Number, Value};
use std::collections::HashMap;
use std::env;
use std::io;

/// Zerobus writer used by the CLI.
pub struct ZerobusWriter {
    inner: PlatformZerobusWriter,
}

impl ZerobusWriter {
    pub fn new(config: &ZerobusOutputConfig) -> io::Result<Self> {
        Ok(Self {
            inner: build_platform_writer(config)?,
        })
    }

    pub fn run_id(&self) -> &str {
        self.inner.run_id()
    }

    pub fn write_json_record(&mut self, source: &str, row: String) -> io::Result<u64> {
        self.inner.write_json_record(source, row)
    }
}

impl EventWriter for ZerobusWriter {
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

#[cfg(feature = "zerobus")]
type PlatformZerobusWriter = ZerobusBatchWriter<RealZerobusFactory>;

#[cfg(not(feature = "zerobus"))]
struct PlatformZerobusWriter;

#[cfg(feature = "zerobus")]
fn build_platform_writer(config: &ZerobusOutputConfig) -> io::Result<PlatformZerobusWriter> {
    let factory = RealZerobusFactory::from_config(config)?;
    ZerobusBatchWriter::new(config, factory)
}

#[cfg(not(feature = "zerobus"))]
fn build_platform_writer(config: &ZerobusOutputConfig) -> io::Result<PlatformZerobusWriter> {
    PlatformZerobusWriter::new(config)
}

#[cfg(not(feature = "zerobus"))]
impl PlatformZerobusWriter {
    fn new(_config: &ZerobusOutputConfig) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "zerobus output requires building with --features zerobus",
        ))
    }

    fn write_event(&mut self, _event: &Event) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "zerobus output requires building with --features zerobus",
        ))
    }

    fn write_json_record(&mut self, _source: &str, _row: String) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "zerobus output requires building with --features zerobus",
        ))
    }

    fn run_id(&self) -> &str {
        ""
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

trait ZerobusStreamClient {
    fn ingest_records(&mut self, records: Vec<String>) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
    fn close(&mut self) -> io::Result<()>;
}

trait ZerobusStreamFactory {
    type Stream: ZerobusStreamClient;

    fn open_stream(&mut self, source: &str, table: &str) -> io::Result<Self::Stream>;
}

struct ZerobusBatchWriter<F: ZerobusStreamFactory> {
    factory: F,
    routes: HashMap<String, ZerobusRoute<F::Stream>>,
    batch_size: usize,
    run_id: String,
}

struct ZerobusRoute<S: ZerobusStreamClient> {
    table: String,
    stream: Option<S>,
    batch: Vec<String>,
}

impl<F: ZerobusStreamFactory> ZerobusBatchWriter<F> {
    fn new(config: &ZerobusOutputConfig, factory: F) -> io::Result<Self> {
        validate_tables(&config.tables)?;
        let routes = config
            .tables
            .iter()
            .map(|(source, table)| {
                (
                    source.clone(),
                    ZerobusRoute {
                        table: table.clone(),
                        stream: None,
                        batch: Vec::new(),
                    },
                )
            })
            .collect();

        Ok(Self {
            factory,
            routes,
            batch_size: config.batch_size.max(1),
            run_id: config.run_id.clone().unwrap_or_else(default_run_id),
        })
    }

    fn write_event(&mut self, event: &Event) -> io::Result<u64> {
        let source = event.envelope.source.clone();
        let row = event_to_row_json(event, &self.run_id, Utc::now())?;
        self.write_json_record(&source, row)
    }

    fn write_json_record(&mut self, source: &str, row: String) -> io::Result<u64> {
        let size = row.len() as u64;
        let route = self.route_mut(source)?;
        route.batch.push(row);
        if route.batch.len() >= self.batch_size {
            self.send_source_batch(source)?;
        }
        Ok(size)
    }

    fn run_id(&self) -> &str {
        &self.run_id
    }

    fn flush(&mut self) -> io::Result<()> {
        let sources = self.routes.keys().cloned().collect::<Vec<_>>();
        for source in sources {
            self.flush_source(&source)?;
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        self.flush()?;
        for route in self.routes.values_mut() {
            if let Some(stream) = route.stream.as_mut() {
                stream.close()?;
            }
        }
        Ok(())
    }

    fn route_mut(&mut self, source: &str) -> io::Result<&mut ZerobusRoute<F::Stream>> {
        self.routes.get_mut(source).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("no zerobus table configured for source {source}"),
            )
        })
    }

    fn flush_source(&mut self, source: &str) -> io::Result<()> {
        self.send_source_batch(source)?;

        let route = self.route_mut(source)?;
        if let Some(stream) = route.stream.as_mut() {
            stream.flush()?;
        }
        Ok(())
    }

    fn send_source_batch(&mut self, source: &str) -> io::Result<()> {
        let has_batch = {
            let route = self.route_mut(source)?;
            !route.batch.is_empty()
        };
        if !has_batch {
            return Ok(());
        }

        self.ensure_stream(source)?;
        let route = self.route_mut(source)?;
        let batch = std::mem::take(&mut route.batch);
        route.stream.as_mut().unwrap().ingest_records(batch)
    }

    fn ensure_stream(&mut self, source: &str) -> io::Result<()> {
        let needs_stream = self.route_mut(source)?.stream.is_none();
        if !needs_stream {
            return Ok(());
        }

        let table = self.route_mut(source)?.table.clone();
        let stream = self.factory.open_stream(source, &table)?;
        self.route_mut(source)?.stream = Some(stream);
        Ok(())
    }
}

fn validate_tables(tables: &HashMap<String, String>) -> io::Result<()> {
    if tables.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zerobus output requires at least one table route",
        ));
    }
    for (source, table) in tables {
        if source.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zerobus table source keys must be non-empty",
            ));
        }
        if table.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("zerobus table for source {source} must be non-empty"),
            ));
        }
    }
    Ok(())
}

fn event_to_row_json(
    event: &Event,
    run_id: &str,
    generated_at: DateTime<Utc>,
) -> io::Result<String> {
    let parsed_time = DateTime::parse_from_rfc3339(&event.envelope.timestamp)
        .ok()
        .map(|value| value.with_timezone(&Utc));
    let event_date = parsed_time
        .as_ref()
        .map(|value| value.format("%Y-%m-%d").to_string());
    let event_ts_ms = parsed_time.as_ref().map(|value| value.timestamp_millis());
    let time = parsed_time.as_ref().map(|value| value.timestamp_micros());
    let envelope_json = serde_json::to_string(&event.envelope)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    let payload_json = serde_json::to_string(&event.payload)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

    let row = json!({
        "time": time.map(Number::from).map(Value::Number),
        "event_time": event.envelope.timestamp.clone(),
        "event_date": event_date,
        "event_ts_ms": event_ts_ms.map(Number::from).map(Value::Number),
        "source": event.envelope.source.clone(),
        "event_type": event.envelope.event_type.clone(),
        "actor_id": event.envelope.actor.id.clone(),
        "actor_kind": event.envelope.actor.kind.clone(),
        "actor_name": event.envelope.actor.name.clone(),
        "target_id": event.envelope.target.as_ref().map(|target| target.id.clone()),
        "target_kind": event.envelope.target.as_ref().map(|target| target.kind.clone()),
        "target_name": event.envelope.target.as_ref().and_then(|target| target.name.clone()),
        "outcome": outcome_to_str(&event.envelope.outcome),
        "ip": event.envelope.ip.clone(),
        "user_agent": event.envelope.user_agent.clone(),
        "session_id": event.envelope.session_id.clone(),
        "tenant_id": event.envelope.tenant_id.clone(),
        "envelope_json": envelope_json,
        "payload_json": payload_json,
        "run_id": run_id,
        "generated_at": generated_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    });

    serde_json::to_string(&row).map_err(|err| io::Error::new(io::ErrorKind::Other, err))
}

fn outcome_to_str(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Success => "success",
        Outcome::Failure => "failure",
        Outcome::Unknown => "unknown",
    }
}

fn default_run_id() -> String {
    format!(
        "seclog-{}",
        Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
    )
}

fn read_required_env(name: &str, label: &str) -> io::Result<String> {
    let value = env::var(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("zerobus {label} env var {name} is not set"),
        )
    })?;
    if value.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("zerobus {label} env var {name} is empty"),
        ));
    }
    Ok(value)
}

#[cfg(feature = "zerobus")]
struct RealZerobusFactory {
    runtime: std::sync::Arc<tokio::runtime::Runtime>,
    sdk: databricks_zerobus_ingest_sdk::ZerobusSdk,
    client_id: String,
    client_secret: String,
    max_inflight_requests: usize,
}

#[cfg(feature = "zerobus")]
impl RealZerobusFactory {
    fn from_config(config: &ZerobusOutputConfig) -> io::Result<Self> {
        let client_id = read_required_env(&config.client_id_env, "client id")?;
        let client_secret = read_required_env(&config.client_secret_env, "client secret")?;
        let runtime = std::sync::Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?,
        );
        let sdk = databricks_zerobus_ingest_sdk::ZerobusSdk::builder()
            .endpoint(config.endpoint.clone())
            .unity_catalog_url(config.workspace_url.clone())
            .build()
            .map_err(map_zerobus_err)?;
        Ok(Self {
            runtime,
            sdk,
            client_id,
            client_secret,
            max_inflight_requests: config.max_inflight_requests.max(1),
        })
    }
}

#[cfg(feature = "zerobus")]
impl ZerobusStreamFactory for RealZerobusFactory {
    type Stream = RealZerobusStream;

    fn open_stream(&mut self, _source: &str, table: &str) -> io::Result<Self::Stream> {
        let runtime = std::sync::Arc::clone(&self.runtime);
        let table = table.to_string();
        let client_id = self.client_id.clone();
        let client_secret = self.client_secret.clone();
        let max_inflight_requests = self.max_inflight_requests;
        let stream = runtime.block_on(async {
            self.sdk
                .stream_builder()
                .table(table)
                .oauth(client_id, client_secret)
                .json()
                .max_inflight_requests(max_inflight_requests)
                .build()
                .await
        });
        let stream = stream.map_err(map_zerobus_err)?;
        Ok(RealZerobusStream { runtime, stream })
    }
}

#[cfg(feature = "zerobus")]
struct RealZerobusStream {
    runtime: std::sync::Arc<tokio::runtime::Runtime>,
    stream: databricks_zerobus_ingest_sdk::ZerobusStream,
}

#[cfg(feature = "zerobus")]
impl ZerobusStreamClient for RealZerobusStream {
    fn ingest_records(&mut self, records: Vec<String>) -> io::Result<()> {
        let records = records
            .into_iter()
            .map(databricks_zerobus_ingest_sdk::JsonString)
            .collect::<Vec<_>>();
        let runtime = std::sync::Arc::clone(&self.runtime);
        runtime
            .block_on(async {
                self.stream.ingest_records_offset(records).await?;
                Ok::<(), databricks_zerobus_ingest_sdk::ZerobusError>(())
            })
            .map_err(map_zerobus_err)
    }

    fn flush(&mut self) -> io::Result<()> {
        let runtime = std::sync::Arc::clone(&self.runtime);
        runtime
            .block_on(self.stream.flush())
            .map_err(map_zerobus_err)
    }

    fn close(&mut self) -> io::Result<()> {
        let runtime = std::sync::Arc::clone(&self.runtime);
        runtime
            .block_on(self.stream.close())
            .map_err(map_zerobus_err)
    }
}

#[cfg(feature = "zerobus")]
fn map_zerobus_err(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("zerobus ingest error: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{Actor, EventEnvelope};
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct FakeState {
        opened: Rc<RefCell<Vec<(String, String)>>>,
        ingested: Rc<RefCell<HashMap<String, Vec<Vec<String>>>>>,
        flushes: Rc<RefCell<Vec<String>>>,
        closes: Rc<RefCell<Vec<String>>>,
    }

    struct FakeFactory {
        state: FakeState,
    }

    struct FakeStream {
        source: String,
        state: FakeState,
    }

    impl ZerobusStreamFactory for FakeFactory {
        type Stream = FakeStream;

        fn open_stream(&mut self, source: &str, table: &str) -> io::Result<Self::Stream> {
            self.state
                .opened
                .borrow_mut()
                .push((source.to_string(), table.to_string()));
            Ok(FakeStream {
                source: source.to_string(),
                state: self.state.clone(),
            })
        }
    }

    impl ZerobusStreamClient for FakeStream {
        fn ingest_records(&mut self, records: Vec<String>) -> io::Result<()> {
            self.state
                .ingested
                .borrow_mut()
                .entry(self.source.clone())
                .or_default()
                .push(records);
            Ok(())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.state.flushes.borrow_mut().push(self.source.clone());
            Ok(())
        }

        fn close(&mut self) -> io::Result<()> {
            self.state.closes.borrow_mut().push(self.source.clone());
            Ok(())
        }
    }

    #[test]
    fn event_to_row_preserves_payload_json() {
        let event = test_event("okta_system_log", "user.session.start");
        let row = event_to_row_json(
            &event,
            "run-1",
            DateTime::parse_from_rfc3339("2026-01-01T00:01:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap();
        let row: Value = serde_json::from_str(&row).unwrap();

        assert_eq!(row["source"], "okta_system_log");
        assert_eq!(row["time"], 1767225600000000_i64);
        assert_eq!(row["event_date"], "2026-01-01");
        assert_eq!(row["event_ts_ms"], 1767225600000_i64);
        assert_eq!(row["run_id"], "run-1");
        assert_eq!(
            serde_json::from_str::<Value>(row["payload_json"].as_str().unwrap()).unwrap(),
            json!({"eventType": "user.session.start"})
        );
    }

    #[test]
    fn batches_and_routes_by_source() {
        let state = FakeState::default();
        let config = test_config(2);
        let factory = FakeFactory {
            state: state.clone(),
        };
        let mut writer = ZerobusBatchWriter::new(&config, factory).unwrap();

        writer
            .write_event(&test_event("cloudtrail", "ConsoleLogin"))
            .unwrap();
        writer
            .write_event(&test_event("okta_system_log", "user.session.start"))
            .unwrap();
        writer
            .write_event(&test_event("cloudtrail", "AssumeRole"))
            .unwrap();
        writer.flush().unwrap();
        writer.close().unwrap();

        let opened = state.opened.borrow();
        assert!(opened.contains(&(
            "cloudtrail".to_string(),
            "main.seclog.cloudtrail_events".to_string()
        )));
        assert!(opened.contains(&(
            "okta_system_log".to_string(),
            "main.seclog.okta_system_log_events".to_string()
        )));

        let ingested = state.ingested.borrow();
        assert_eq!(ingested["cloudtrail"][0].len(), 2);
        assert_eq!(ingested["okta_system_log"][0].len(), 1);
        assert!(state.flushes.borrow().contains(&"cloudtrail".to_string()));
        assert!(state.closes.borrow().contains(&"cloudtrail".to_string()));
    }

    #[test]
    fn missing_source_table_is_deterministic_error() {
        let config = test_config(10);
        let factory = FakeFactory {
            state: FakeState::default(),
        };
        let mut writer = ZerobusBatchWriter::new(&config, factory).unwrap();
        let err = writer
            .write_event(&test_event("databricks_audit", "IpAccessDenied"))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "no zerobus table configured for source databricks_audit"
        );
    }

    #[test]
    fn raw_json_records_route_to_non_event_tables() {
        let state = FakeState::default();
        let config = test_config(1);
        let factory = FakeFactory {
            state: state.clone(),
        };
        let mut writer = ZerobusBatchWriter::new(&config, factory).unwrap();

        assert_eq!(writer.run_id(), "run-1");
        writer
            .write_json_record(
                "actor_population",
                json!({"actor_id": "user-001"}).to_string(),
            )
            .unwrap();
        writer.close().unwrap();

        let opened = state.opened.borrow();
        assert!(opened.contains(&(
            "actor_population".to_string(),
            "main.seclog.actor_population".to_string()
        )));

        let ingested = state.ingested.borrow();
        assert_eq!(ingested["actor_population"][0].len(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(&ingested["actor_population"][0][0]).unwrap(),
            json!({"actor_id": "user-001"})
        );
    }

    #[test]
    fn missing_credential_env_var_is_redacted() {
        env::remove_var("SECLOG_TEST_MISSING_ZEROBUS_CLIENT_ID");
        let err =
            read_required_env("SECLOG_TEST_MISSING_ZEROBUS_CLIENT_ID", "client id").unwrap_err();
        assert_eq!(
            err.to_string(),
            "zerobus client id env var SECLOG_TEST_MISSING_ZEROBUS_CLIENT_ID is not set"
        );
    }

    fn test_config(batch_size: usize) -> ZerobusOutputConfig {
        ZerobusOutputConfig {
            output_type: crate::core::config::ZerobusOutputType::Zerobus,
            workspace_url: "https://dbc-example.cloud.databricks.com".to_string(),
            endpoint: "https://1234567890123456.zerobus.us-west-2.cloud.databricks.com".to_string(),
            client_id_env: "DATABRICKS_CLIENT_ID".to_string(),
            client_secret_env: "DATABRICKS_CLIENT_SECRET".to_string(),
            batch_size,
            max_inflight_requests: 100,
            flush_interval_ms: 1_000,
            run_id: Some("run-1".to_string()),
            tables: HashMap::from([
                (
                    "cloudtrail".to_string(),
                    "main.seclog.cloudtrail_events".to_string(),
                ),
                (
                    "okta_system_log".to_string(),
                    "main.seclog.okta_system_log_events".to_string(),
                ),
                (
                    "actor_population".to_string(),
                    "main.seclog.actor_population".to_string(),
                ),
            ]),
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
                    name: Some("User One".to_string()),
                },
                target: None,
                outcome: Outcome::Success,
                geo: None,
                ip: Some("198.51.100.10".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
                session_id: Some("session-1".to_string()),
                tenant_id: Some("tenant-1".to_string()),
            },
            payload: json!({ "eventType": event_type }),
        }
    }
}
