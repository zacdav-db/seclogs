-- DuckDB summary checks.
-- Update the path to your parquet output before running.
CREATE OR REPLACE VIEW events AS
SELECT
  envelope.actor.id AS actor_id,
  coalesce(envelope.actor.name, cloudtrail.userIdentity.userName) AS actor_name,
  envelope.actor.kind AS actor_kind,
  envelope.event_type AS event_name,
  envelope.source AS source,
  envelope.timestamp AS ts_raw,
  coalesce(
    try_cast(envelope.timestamp AS TIMESTAMP),
    try_cast(cloudtrail.eventTime AS TIMESTAMP)
  ) AS ts_parsed,
  envelope.outcome AS outcome,
  coalesce(envelope.user_agent, cloudtrail.userAgent) AS user_agent,
  cloudtrail.eventSource AS event_source,
  cloudtrail.awsRegion AS aws_region,
  cloudtrail.recipientAccountId AS account_id,
  cloudtrail.errorCode AS error_code,
  cloudtrail.errorMessage AS error_message
FROM read_parquet('out-test/*.parquet');

SELECT count(*) AS total_events FROM events;

SELECT
  event_name,
  outcome,
  count(*) AS total
FROM events
GROUP BY 1, 2
ORDER BY total DESC;

SELECT
  user_agent,
  count(*) AS total
FROM events
WHERE user_agent IS NOT NULL
GROUP BY 1
ORDER BY total DESC
LIMIT 20;

SELECT
  actor_id,
  actor_name,
  count(*) AS total
FROM events
GROUP BY 1, 2
ORDER BY total DESC
LIMIT 20;

SELECT
  aws_region,
  count(*) AS total
FROM events
GROUP BY 1
ORDER BY total DESC;

-- 5-minute trend totals.
WITH buckets AS (
  SELECT
    date_trunc('minute', ts_parsed)
      - (extract(minute FROM ts_parsed)::INT % 5) * INTERVAL '1 minute' AS bucket_5m
  FROM events
  WHERE ts_parsed IS NOT NULL
)
SELECT
  bucket_5m,
  count(*) AS total
FROM buckets
GROUP BY 1
ORDER BY 1;

-- 5-minute trend by region.
WITH buckets AS (
  SELECT
    date_trunc('minute', ts_parsed)
      - (extract(minute FROM ts_parsed)::INT % 5) * INTERVAL '1 minute' AS bucket_5m,
    aws_region
  FROM events
  WHERE ts_parsed IS NOT NULL
)
SELECT
  bucket_5m,
  aws_region,
  count(*) AS total
FROM buckets
GROUP BY 1, 2
ORDER BY 1, 2;

-- 5-minute trend by event type.
WITH buckets AS (
  SELECT
    date_trunc('minute', ts_parsed)
      - (extract(minute FROM ts_parsed)::INT % 5) * INTERVAL '1 minute' AS bucket_5m,
    event_name
  FROM events
  WHERE ts_parsed IS NOT NULL
)
SELECT
  bucket_5m,
  event_name,
  count(*) AS total
FROM buckets
GROUP BY 1, 2
ORDER BY 1, 2;

-- Optional: export trend data for charting.
-- COPY (
--   WITH buckets AS (
--     SELECT
--       date_trunc('minute', ts_parsed)
--         - (extract(minute FROM ts_parsed)::INT % 5) * INTERVAL '1 minute' AS bucket_5m,
--       aws_region,
--       event_name
--     FROM events
--     WHERE ts_parsed IS NOT NULL
--   )
--   SELECT bucket_5m, aws_region, event_name, count(*) AS total
--   FROM buckets
--   GROUP BY 1, 2, 3
--   ORDER BY 1, 2, 3
-- ) TO 'out-test/trend_5m.csv' (HEADER, DELIMITER ',');
