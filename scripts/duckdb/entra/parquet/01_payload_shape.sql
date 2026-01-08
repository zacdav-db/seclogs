-- DuckDB Entra ID payload shape checks.
-- Update the path to your parquet output before running.
CREATE OR REPLACE VIEW entra_events AS
SELECT
  envelope.timestamp AS envelope_ts,
  envelope.event_type AS event_type,
  envelope.actor.id AS actor_id,
  envelope.actor.kind AS actor_kind,
  envelope.actor.name AS actor_name,
  envelope.outcome AS outcome,
  payload_json,
  try_cast(json_extract_string(payload_json, '$.createdDateTime') AS TIMESTAMP) AS signin_ts,
  try_cast(json_extract_string(payload_json, '$.activityDateTime') AS TIMESTAMP) AS audit_ts,
  json_extract_string(payload_json, '$.appDisplayName') AS app_display_name,
  json_extract_string(payload_json, '$.activityDisplayName') AS activity_display_name,
  json_extract_string(payload_json, '$.category') AS audit_category,
  try_cast(json_extract(payload_json, '$.status.errorCode') AS BIGINT) AS signin_error_code,
  json_extract_string(payload_json, '$.status.failureReason') AS signin_failure_reason,
  json_extract_string(payload_json, '$.clientAppUsed') AS client_app_used,
  json_extract_string(payload_json, '$.ipAddress') AS ip_address,
  json_extract_string(payload_json, '$.location.countryOrRegion') AS country_or_region,
  json_extract_string(payload_json, '$.deviceDetail.operatingSystem') AS operating_system
FROM read_parquet('out-test/entra_id/*.parquet');

SELECT count(*) AS total_events FROM entra_events;

-- Sign-in payload shape.
SELECT
  event_type,
  signin_ts,
  app_display_name,
  client_app_used,
  signin_error_code,
  signin_failure_reason,
  ip_address,
  operating_system,
  country_or_region
FROM entra_events
WHERE signin_ts IS NOT NULL
ORDER BY signin_ts
LIMIT 20;

-- Audit payload shape.
SELECT
  event_type,
  audit_ts,
  activity_display_name,
  audit_category,
  json_extract_string(payload_json, '$.initiatedBy.user.userPrincipalName') AS initiated_user_upn,
  json_extract_string(payload_json, '$.initiatedBy.app.servicePrincipalName') AS initiated_app,
  json_extract_string(payload_json, '$.loggedByService') AS logged_by_service,
  json_extract_string(payload_json, '$.result') AS result
FROM entra_events
WHERE audit_ts IS NOT NULL
ORDER BY audit_ts
LIMIT 20;

-- Example payloads (one of each).
SELECT payload_json
FROM entra_events
WHERE signin_ts IS NOT NULL
ORDER BY random()
LIMIT 1;

SELECT payload_json
FROM entra_events
WHERE audit_ts IS NOT NULL
ORDER BY random()
LIMIT 1;
