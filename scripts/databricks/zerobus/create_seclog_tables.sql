-- Pre-create managed Delta tables for seclog Zerobus ingestion.
-- Adjust catalog and schema names before running if needed.

CREATE SCHEMA IF NOT EXISTS main.seclog;

CREATE TABLE IF NOT EXISTS main.seclog.cloudtrail_events (
  event_time STRING,
  event_date STRING,
  event_ts_ms BIGINT,
  source STRING,
  event_type STRING,
  actor_id STRING,
  actor_kind STRING,
  actor_name STRING,
  target_id STRING,
  target_kind STRING,
  target_name STRING,
  outcome STRING,
  ip STRING,
  user_agent STRING,
  session_id STRING,
  tenant_id STRING,
  envelope_json STRING,
  payload_json STRING,
  run_id STRING,
  generated_at STRING
) USING DELTA;

CREATE TABLE IF NOT EXISTS main.seclog.databricks_audit_events (
  event_time STRING,
  event_date STRING,
  event_ts_ms BIGINT,
  source STRING,
  event_type STRING,
  actor_id STRING,
  actor_kind STRING,
  actor_name STRING,
  target_id STRING,
  target_kind STRING,
  target_name STRING,
  outcome STRING,
  ip STRING,
  user_agent STRING,
  session_id STRING,
  tenant_id STRING,
  envelope_json STRING,
  payload_json STRING,
  run_id STRING,
  generated_at STRING
) USING DELTA;

CREATE TABLE IF NOT EXISTS main.seclog.okta_system_log_events (
  event_time STRING,
  event_date STRING,
  event_ts_ms BIGINT,
  source STRING,
  event_type STRING,
  actor_id STRING,
  actor_kind STRING,
  actor_name STRING,
  target_id STRING,
  target_kind STRING,
  target_name STRING,
  outcome STRING,
  ip STRING,
  user_agent STRING,
  session_id STRING,
  tenant_id STRING,
  envelope_json STRING,
  payload_json STRING,
  run_id STRING,
  generated_at STRING
) USING DELTA;
