-- Sequence checks for expected transitions.
-- Update the path to your parquet output before running.
CREATE OR REPLACE VIEW events AS
SELECT
  envelope.actor.id AS actor_id,
  envelope.event_type AS event_name,
  coalesce(
    try_cast(envelope.timestamp AS TIMESTAMP),
    try_cast(cloudtrail.event_time AS TIMESTAMP)
  ) AS ts_parsed,
  coalesce(envelope.user_agent, cloudtrail.user_agent) AS user_agent
FROM read_parquet('out-test/*.parquet');

WITH ordered AS (
  SELECT
    actor_id,
    event_name,
    ts_parsed,
    lag(event_name) OVER (
      PARTITION BY actor_id
      ORDER BY ts_parsed
    ) AS prev_event
  FROM events
  WHERE ts_parsed IS NOT NULL
)
SELECT
  prev_event,
  event_name,
  count(*) AS transitions
FROM ordered
WHERE prev_event IS NOT NULL
GROUP BY 1, 2
ORDER BY transitions DESC
LIMIT 50;

WITH ordered AS (
  SELECT
    actor_id,
    event_name,
    ts_parsed,
    lag(event_name) OVER (
      PARTITION BY actor_id
      ORDER BY ts_parsed
    ) AS prev_event
  FROM events
  WHERE ts_parsed IS NOT NULL
)
SELECT
  sum(CASE WHEN event_name = 'AssumeRole'
        AND prev_event IN ('ConsoleLogin', 'GetSessionToken')
      THEN 1 ELSE 0 END) AS expected,
  sum(CASE WHEN event_name = 'AssumeRole' THEN 1 ELSE 0 END) AS total,
  round(100.0 * expected / NULLIF(total, 0), 2) AS pct_expected
FROM ordered;

WITH ordered AS (
  SELECT
    actor_id,
    event_name,
    ts_parsed,
    lag(event_name) OVER (
      PARTITION BY actor_id
      ORDER BY ts_parsed
    ) AS prev_event
  FROM events
  WHERE ts_parsed IS NOT NULL
)
SELECT
  sum(CASE WHEN event_name IN ('PutObject', 'GetObject')
        AND prev_event IN ('AssumeRole', 'GetSessionToken')
      THEN 1 ELSE 0 END) AS expected,
  sum(CASE WHEN event_name IN ('PutObject', 'GetObject') THEN 1 ELSE 0 END) AS total,
  round(100.0 * expected / NULLIF(total, 0), 2) AS pct_expected
FROM ordered;
