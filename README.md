# Seclog

High-volume SIEM log generator with CloudTrail-style data.

> [!NOTE]
> This project is under active development.

## Documentation
- Rustdoc is the primary reference and is published to GitHub Pages.
- Build locally with `cargo doc --workspace --no-deps`.

## Getting started (end-to-end)
1. Generate an actor population (Parquet):
```bash
cargo run --bin seclog-cli -- actors --config examples/actors.toml --output ./actors.parquet
```
2. Generate CloudTrail logs using that population:
```bash
cargo run --bin seclog-cli -- gen --config examples/config.toml --output ./out-test
```

## actors.toml reference (population generation)
Top-level:
- `seed` (optional, integer): RNG seed for deterministic populations.
- `timezone_distribution` (optional, list):
  - `name` (string): IANA timezone name, e.g. `America/Los_Angeles`.
  - `weight` (float): Relative weight; higher means more actors in that zone.
- `population` (required table): population parameters (see below).

`[population]`:
- `actor_count` (optional, int): total actors (default 500).
- `service_ratio` (optional, float): fraction of service actors, 0.0–1.0 (default 0.2).
- `hot_actor_ratio` (optional, float): fraction of actors boosted by multiplier (default 0.1).
- `hot_actor_multiplier` (optional, float): multiplier for hot actors (default 6.0).
- `account_ids` (optional, list[string]): explicit AWS account IDs (12-digit).
- `account_count` (optional, int): number of random account IDs if none provided (default 1).
- `role_distribution` (optional, list):
  - `name`: `admin` | `developer` | `readonly` | `auditor`.
  - `weight`: relative weight across roles.
- `role_rates_per_hour` (optional, list):
  - `name`: `admin` | `developer` | `readonly` | `auditor`.
  - `rate_per_hour`: events/hour baseline for that role.
- `service_rate_per_hour` (optional, float): default rate for service actors (default 6.0).
- `service_profiles` (optional, list):
  - `name`: `generic` | `ec2_reaper` | `datalake_bot` | `logs_shipper` | `metrics_collector`.
  - `weight`: relative selection weight across profiles.
  - `rate_per_hour` (optional): overrides `service_rate_per_hour`.
  - `pattern` (optional): `constant` | `diurnal` | `bursty`.

Example: `examples/actors.toml`.

## config.toml reference (log generation)
Top-level:
- `seed` (optional, integer): RNG seed for deterministic generation.
- `traffic` (required table):
  - `start_time` (optional, RFC3339): simulated clock start (defaults to now).
  - `time_scale` (optional, float): 1.0 = real time, 100.0 = 100x faster.
- `output` (required table):
  - `dir` (string): output directory.
  - `rotation` (table):
    - `target_size_mb` (int): target file size before rotation.
    - `flush_interval_ms` (optional, int): flush interval for buffered writers.
    - `max_age_seconds` (optional, int): rotate if file is older than this.
  - `format` (table):
    - `type`: `parquet` | `jsonl`.
    - `compression` (optional):
      - `jsonl`: supports `gzip` (writes `.json.gz` CloudTrail records).
      - `parquet`: currently uses default writer settings (compression not wired).
- `source` (required table):
  - `type`: `cloudtrail`.
  - `curated` (bool): load curated event weights.
  - `actor_population_path` (string): path to the actors parquet (required).
  - `regions` (optional, list[string]): allowed AWS regions.
  - `region_distribution` (optional, list):
    - `name`: region name.
    - `weight`: relative selection weight.
  - `custom_events` (optional, list):
    - `name`: CloudTrail event name.
    - `weight`: relative weight; overrides curated weight if name matches.
  - `error_rates` (optional, list):
    - `name`: CloudTrail event name.
    - `rate`: 0.0–1.0 error rate.
    - `code` (optional): error code to emit.
    - `message` (optional): error message to emit.

Example: `examples/config.toml`.

## DuckDB validation
Run the analysis scripts against generated Parquet logs:
```bash
duckdb -c ".read scripts/duckdb/01_summary.sql"
duckdb -c ".read scripts/duckdb/02_sequences.sql"
duckdb -c ".read scripts/duckdb/03_errors.sql"
duckdb -c ".read scripts/duckdb/04_actor_chains.sql"
```
