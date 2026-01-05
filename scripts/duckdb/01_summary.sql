-- DuckDB summary checks.
-- Update the path to your parquet output before running.
CREATE OR REPLACE VIEW events AS
SELECT
  envelope.actor.id AS actor_id,
  envelope.actor.name AS actor_name,
  envelope.event_type AS event_name,
  envelope.timestamp AS ts,
  try_cast(envelope.timestamp AS TIMESTAMP) AS ts_parsed,
  envelope.outcome AS outcome,
  envelope.user_agent AS user_agent,
  cloudtrail.event_source AS event_source,
  cloudtrail.aws_region AS aws_region,
  cloudtrail.error_code AS error_code,
  cloudtrail.error_message AS error_message
FROM read_parquet('out-test-5/events-*.parquet');

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
