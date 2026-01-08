-- Actor-level chain inspection and sequencing validity checks.
-- Update the path to your parquet output before running.
CREATE OR REPLACE VIEW events AS
SELECT
  envelope.actor.id AS actor_id,
  envelope.event_type AS event_name,
  coalesce(
    try_cast(envelope.timestamp AS TIMESTAMP),
    try_cast(cloudtrail.eventTime AS TIMESTAMP)
  ) AS ts_parsed
FROM read_parquet('out-test/cloudtrail/*.parquet');

-- Allowed transitions (extend as needed).
WITH allowed AS (
  SELECT * FROM (VALUES
    (NULL, 'ConsoleLogin'),
    (NULL, 'GetSessionToken'),
    (NULL, 'AssumeRole'),
    ('ConsoleLogin', 'GetSessionToken'),
    ('ConsoleLogin', 'AssumeRole'),
    ('GetSessionToken', 'AssumeRole'),
    ('AssumeRole', 'GetObject'),
    ('AssumeRole', 'PutObject'),
    ('AssumeRole', 'RunInstances'),
    ('AssumeRole', 'DescribeInstances'),
    ('GetSessionToken', 'GetObject'),
    ('GetSessionToken', 'PutObject'),
    ('GetSessionToken', 'DescribeInstances'),
    ('GetObject', 'GetObject'),
    ('PutObject', 'PutObject'),
    ('DescribeInstances', 'DescribeInstances'),
    ('PutLogEvents', 'PutLogEvents'),
    ('CreateLogGroup', 'PutLogEvents')
  ) AS t(prev_event, event_name)
),
ordered AS (
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
),
checked AS (
  SELECT
    actor_id,
    prev_event,
    event_name,
    ts_parsed,
    CASE
      WHEN prev_event IS NULL THEN true
      WHEN EXISTS (
        SELECT 1
        FROM allowed a
        WHERE a.prev_event = prev_event
          AND a.event_name = event_name
      ) THEN true
      ELSE false
    END AS is_valid
  FROM ordered
)
SELECT
  sum(CASE WHEN is_valid THEN 0 ELSE 1 END) AS invalid_transitions,
  count(*) AS total_transitions,
  round(100.0 * invalid_transitions / NULLIF(total_transitions, 0), 2) AS invalid_pct
FROM checked;

-- Actors with the most invalid transitions.
WITH checked AS (
  SELECT
    actor_id,
    prev_event,
    event_name,
    ts_parsed,
    CASE
      WHEN prev_event IS NULL THEN true
      WHEN EXISTS (
        SELECT 1
        FROM (VALUES
          (NULL, 'ConsoleLogin'),
          (NULL, 'GetSessionToken'),
          (NULL, 'AssumeRole'),
          ('ConsoleLogin', 'GetSessionToken'),
          ('ConsoleLogin', 'AssumeRole'),
          ('GetSessionToken', 'AssumeRole'),
          ('AssumeRole', 'GetObject'),
          ('AssumeRole', 'PutObject'),
          ('AssumeRole', 'RunInstances'),
          ('AssumeRole', 'DescribeInstances'),
          ('GetSessionToken', 'GetObject'),
          ('GetSessionToken', 'PutObject'),
          ('GetSessionToken', 'DescribeInstances'),
          ('GetObject', 'GetObject'),
          ('PutObject', 'PutObject'),
          ('DescribeInstances', 'DescribeInstances'),
          ('PutLogEvents', 'PutLogEvents'),
          ('CreateLogGroup', 'PutLogEvents')
        ) AS a(prev_event, event_name)
        WHERE a.prev_event = prev_event
          AND a.event_name = event_name
      ) THEN true
      ELSE false
    END AS is_valid
  FROM (
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
  ) ordered
)
SELECT
  actor_id,
  sum(CASE WHEN is_valid THEN 0 ELSE 1 END) AS invalid_transitions,
  count(*) AS total_transitions
FROM checked
GROUP BY 1
HAVING invalid_transitions > 0
ORDER BY invalid_transitions DESC, total_transitions DESC
LIMIT 20;

-- Inspect a random actor chain.
WITH picked AS (
  SELECT actor_id
  FROM events
  WHERE ts_parsed IS NOT NULL
  GROUP BY 1
  ORDER BY random()
  LIMIT 1
)
SELECT
  actor_id,
  event_name,
  ts_parsed,
  lag(ts_parsed) OVER (
    PARTITION BY actor_id
    ORDER BY ts_parsed
  ) AS prev_ts,
  date_diff(
    'minute',
    lag(ts_parsed) OVER (PARTITION BY actor_id ORDER BY ts_parsed),
    ts_parsed
  ) AS gap_minutes,
  lag(event_name) OVER (
    PARTITION BY actor_id
    ORDER BY ts_parsed
  ) AS prev_event
FROM events
WHERE actor_id = (SELECT actor_id FROM picked)
ORDER BY ts_parsed;
