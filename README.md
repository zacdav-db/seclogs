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
`actors.toml` controls how the actor population is built and stored as Parquet.

### Example
```toml
seed = 42

[[timezone_distribution]]
name = "America/Los_Angeles"
weight = 0.63

[population]
actor_count = 800
service_ratio = 0.25
hot_actor_ratio = 0.12
hot_actor_multiplier = 6.0
account_count = 1
service_rate_per_hour = 6.0

[[population.role_distribution]]
name = "admin"
weight = 0.15

[[population.role_rates_per_hour]]
name = "admin"
rate_per_hour = 24.0

[[population.service_profiles]]
name = "datalake_bot"
weight = 0.4
rate_per_hour = 30.0
pattern = "constant"
```

### Fields
| Path | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `seed` | int | no | random | RNG seed for deterministic populations. |
| `[[timezone_distribution]]` | table[] | no | none | IANA timezones with weights. |
| `timezone_distribution.name` | string | yes | - | Timezone name, e.g. `America/Los_Angeles`. |
| `timezone_distribution.weight` | float | yes | - | Relative weighting across timezones. |
| `[population]` | table | yes | - | Population parameters. |
| `population.actor_count` | int | no | 500 | Total number of actors. |
| `population.service_ratio` | float | no | 0.2 | Fraction of actors that are services (0.0–1.0). |
| `population.hot_actor_ratio` | float | no | 0.1 | Fraction of actors with boosted rates. |
| `population.hot_actor_multiplier` | float | no | 6.0 | Rate multiplier for hot actors. |
| `population.account_ids` | string[] | no | none | Explicit 12-digit AWS account IDs. |
| `population.account_count` | int | no | 1 | Number of random account IDs if none provided. |
| `population.role_distribution` | table[] | no | defaults | Role weight overrides. |
| `population.role_rates_per_hour` | table[] | no | defaults | Per-role baseline rate overrides. |
| `population.service_rate_per_hour` | float | no | 6.0 | Baseline rate for service actors. |
| `population.service_profiles` | table[] | no | none | Service profile mix and overrides. |

### Role distribution entries
| Path | Type | Required | Description |
| --- | --- | --- | --- |
| `population.role_distribution.name` | string | yes | `admin` \| `developer` \| `readonly` \| `auditor`. |
| `population.role_distribution.weight` | float | yes | Relative weight across roles. |

### Role rate entries
| Path | Type | Required | Description |
| --- | --- | --- | --- |
| `population.role_rates_per_hour.name` | string | yes | `admin` \| `developer` \| `readonly` \| `auditor`. |
| `population.role_rates_per_hour.rate_per_hour` | float | yes | Events per hour for that role. |

### Service profile entries
| Path | Type | Required | Description |
| --- | --- | --- | --- |
| `population.service_profiles.name` | string | yes | `generic` \| `ec2_reaper` \| `datalake_bot` \| `logs_shipper` \| `metrics_collector`. |
| `population.service_profiles.weight` | float | yes | Relative selection weight across profiles. |
| `population.service_profiles.rate_per_hour` | float | no | Overrides `population.service_rate_per_hour`. |
| `population.service_profiles.pattern` | string | no | `constant` \| `diurnal` \| `bursty`. |

## config.toml reference (log generation)
`config.toml` controls generation, output, and CloudTrail source options.

### Example
```toml
seed = 42

[traffic]
start_time = "2025-12-01T00:00:00Z"
time_scale = 100.0

[output]
dir = "./out-test"

[output.rotation]
target_size_mb = 50
flush_interval_ms = 1000
max_age_seconds = 30

[output.format]
type = "jsonl"
compression = "gzip"

[source]
type = "cloudtrail"
curated = true
actor_population_path = "./actors.parquet"
regions = ["us-east-1", "us-west-2"]

[[source.error_rates]]
name = "ConsoleLogin"
rate = 0.06
code = "SigninFailure"
message = "Failed authentication"
```

### Fields
| Path | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `seed` | int | no | random | RNG seed for deterministic output. |
| `[traffic]` | table | yes | - | Simulated clock controls. |
| `traffic.start_time` | string | no | now | RFC3339 start time for the simulation. |
| `traffic.time_scale` | float | no | 1.0 | 1.0 = real time, 100.0 = 100x. |
| `[output]` | table | yes | - | Output sink configuration. |
| `output.dir` | string | yes | - | Output directory. |
| `[output.rotation]` | table | yes | - | Rotation controls. |
| `output.rotation.target_size_mb` | int | yes | - | Target file size before rotation. |
| `output.rotation.flush_interval_ms` | int | no | 30000 | Flush interval for buffered writers. |
| `output.rotation.max_age_seconds` | int | no | none | Rotate file if older than this. |
| `[output.format]` | table | yes | - | Output format selection. |
| `output.format.type` | string | yes | - | `parquet` or `jsonl`. |
| `output.format.compression` | string | no | none | `jsonl`: `gzip` (writes `.json.gz`). |
| `[source]` | table | yes | - | Source configuration (CloudTrail). |
| `source.type` | string | yes | - | `cloudtrail`. |
| `source.curated` | bool | yes | - | Use curated event weights. |
| `source.actor_population_path` | string | yes | - | Path to actors parquet file. |
| `source.regions` | string[] | no | defaults | Allowed AWS regions. |
| `source.region_distribution` | table[] | no | none | Weighted region selection. |
| `source.custom_events` | table[] | no | none | Event weight overrides. |
| `source.error_rates` | table[] | no | none | Per-event error injection. |

### Region distribution entries
| Path | Type | Required | Description |
| --- | --- | --- | --- |
| `source.region_distribution.name` | string | yes | Region name (e.g. `us-east-1`). |
| `source.region_distribution.weight` | float | yes | Relative weight across regions. |

### Custom event entries
| Path | Type | Required | Description |
| --- | --- | --- | --- |
| `source.custom_events.name` | string | yes | CloudTrail event name. |
| `source.custom_events.weight` | float | yes | Relative weight (overrides curated). |

### Error rate entries
| Path | Type | Required | Description |
| --- | --- | --- | --- |
| `source.error_rates.name` | string | yes | CloudTrail event name. |
| `source.error_rates.rate` | float | yes | Error rate (0.0–1.0). |
| `source.error_rates.code` | string | no | Error code to emit. |
| `source.error_rates.message` | string | no | Error message to emit. |

## DuckDB validation
Run the analysis scripts against generated Parquet logs:
```bash
duckdb -c ".read scripts/duckdb/01_summary.sql"
duckdb -c ".read scripts/duckdb/02_sequences.sql"
duckdb -c ".read scripts/duckdb/03_errors.sql"
duckdb -c ".read scripts/duckdb/04_actor_chains.sql"
```
