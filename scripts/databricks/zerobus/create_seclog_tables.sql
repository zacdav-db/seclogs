-- Pre-create managed Delta tables for seclog Zerobus ingestion.
-- Adjust catalog and schema names before running if needed.

CREATE SCHEMA IF NOT EXISTS main.seclog;

CREATE TABLE IF NOT EXISTS main.seclog.cloudtrail_events (
  time TIMESTAMP,
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
  time TIMESTAMP,
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
  time TIMESTAMP,
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

CREATE TABLE IF NOT EXISTS main.seclog.actor_population (
  time TIMESTAMP,
  registry_name STRING,
  actor_id STRING,
  actor_kind STRING,
  email STRING,
  employee_id STRING,
  display_name STRING,
  role_persona STRING,
  department STRING,
  home_location STRING,
  normal_countries_regions_json STRING,
  okta_user_id STRING,
  databricks_username STRING,
  service_account BOOLEAN,
  rate_per_hour DOUBLE,
  active_start_hour INT,
  active_hours INT,
  timezone_offset INT,
  weekend_active BOOLEAN,
  service_pattern STRING,
  tags_json STRING,
  aws_principals_json STRING,
  identity_json STRING,
  run_id STRING,
  generated_at STRING
) USING DELTA;
