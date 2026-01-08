-- Error rate checks by event type and code.
-- Update the path to your parquet output before running.
CREATE OR REPLACE VIEW events AS
SELECT
  envelope.event_type AS event_name,
  envelope.outcome AS outcome,
  cloudtrail.errorCode AS error_code,
  cloudtrail.errorMessage AS error_message
FROM read_parquet('out-test/cloudtrail/*.parquet');

SELECT
  event_name,
  sum(CASE WHEN error_code IS NOT NULL THEN 1 ELSE 0 END) AS errors,
  count(*) AS total,
  round(100.0 * errors / NULLIF(total, 0), 2) AS error_rate_pct
FROM events
GROUP BY 1
ORDER BY error_rate_pct DESC, total DESC;

SELECT
  error_code,
  count(*) AS total
FROM events
WHERE error_code IS NOT NULL
GROUP BY 1
ORDER BY total DESC;

SELECT
  error_code,
  error_message,
  count(*) AS total
FROM events
WHERE error_code IS NOT NULL
GROUP BY 1, 2
ORDER BY total DESC;
