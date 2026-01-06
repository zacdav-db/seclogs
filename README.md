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
Error rates are sampled per actor and applied at generation time; error codes and
messages come from built-in CloudTrail defaults per event.

### Example
```toml
seed = 42 # Optional: set for repeatable populations.

[[timezone_distribution]]
name = "America/Los_Angeles" # IANA timezone.
weight = 0.63 # Higher means more actors in this zone.

[population]
actor_count = 800 # Total actors.
service_ratio = 0.25 # Share of service actors (0.0–1.0).
hot_actor_ratio = 0.12 # Share of hot actors.
hot_actor_multiplier = 6.0 # Rate multiplier for hot actors.
account_count = 1 # Generate this many random account IDs if none provided.
service_events_per_hour = 6.0 # Default events/hour for services.

[population.error_rate]
min = 0.01 # Min per-actor error probability.
max = 0.04 # Max per-actor error probability.
distribution = "uniform" # uniform or normal.

[population.human_error_rate]
min = 0.02
max = 0.06
distribution = "normal" # Concentrated around the mid-point.

[population.service_error_rate]
min = 0.005
max = 0.02
distribution = "uniform"

[[population.role]]
name = "admin"
weight = 0.15 # Higher means more admins in the population.
events_per_hour = 24.0 # Baseline activity rate.

[[population.service_profiles]]
name = "datalake_bot"
weight = 0.4 # Higher means more actors of this profile.
events_per_hour = 30.0 # Overrides service_events_per_hour.
pattern = "constant" # constant, diurnal, or bursty.
```

### Fields
| Path | Type | Required | Default | Effect |
| --- | --- | --- | --- | --- |
| `seed` | int | no | random | Fixes RNG for repeatable populations. |
| `[[timezone_distribution]]` | table[] | no | none | Assigns actor local timezones; affects active windows and diurnal patterns. |
| `timezone_distribution.name` | string | yes | - | IANA timezone name used to compute offsets. |
| `timezone_distribution.weight` | float | yes | - | Higher increases share of actors in that timezone. |
| `[population]` | table | yes | - | Population parameters. |
| `population.actor_count` | int | no | 500 | Raises total volume and unique actor diversity. |
| `population.service_ratio` | float | no | 0.2 | Shifts traffic toward automated events as it increases. |
| `population.hot_actor_ratio` | float | no | 0.1 | Increases number of high-activity actors. |
| `population.hot_actor_multiplier` | float | no | 6.0 | Amplifies activity for hot actors. |
| `population.account_ids` | string[] | no | none | Fixes account IDs for stable, repeatable IDs. |
| `population.account_count` | int | no | 1 | Generates this many random account IDs if none provided. |
| `population.error_rate` | table | no | defaults | Sets baseline per-actor error probability range. |
| `population.human_error_rate` | table | no | baseline | Overrides baseline for humans (often higher auth errors). |
| `population.service_error_rate` | table | no | baseline | Overrides baseline for services (often lower). |
| `population.role` | table[] | no | defaults | Defines role weights and per-role throughput overrides. |
| `population.service_events_per_hour` | float | no | 6.0 | Sets default throughput for services. |
| `population.service_profiles` | table[] | no | none | Controls service profile mix and event families. |

### Role entries
| Path | Type | Required | Effect |
| --- | --- | --- | --- |
| `population.role.name` | string | yes | Selects which role to configure: `admin`, `developer`, `readonly`, `auditor`. |
| `population.role.weight` | float | yes | Higher weight yields more of that role. |
| `population.role.events_per_hour` | float | yes | Baseline events/hour for that role. |

### Role meanings
- `admin`: IAM and security changes, higher propensity for privileged actions (e.g. users, roles, access keys).
- `developer`: EC2/S3 workload activity, resource creation and iteration, moderate privilege usage.
- `readonly`: Mostly read‑only API calls (describe/list/get), lower mutation rate.
- `auditor`: Read‑heavy with frequent logging/monitoring API usage.

### Service profile entries
| Path | Type | Required | Effect |
| --- | --- | --- | --- |
| `population.service_profiles.name` | string | yes | Chooses the service behavior profile. |
| `population.service_profiles.weight` | float | yes | Higher weight increases share of that profile. |
| `population.service_profiles.events_per_hour` | float | no | Overrides `population.service_events_per_hour` for this profile. |
| `population.service_profiles.pattern` | string | no | Shapes activity over time (steady vs. diurnal vs. bursts). |

### Error rate entries
| Path | Type | Required | Effect |
| --- | --- | --- | --- |
| `population.error_rate.min` | float | yes | Lower bound for sampled error rates. |
| `population.error_rate.max` | float | yes | Upper bound for sampled error rates. |
| `population.error_rate.distribution` | string | no | `uniform` spreads evenly; `normal` concentrates around mid-range. |

## config.toml reference (log generation)
`config.toml` controls generation, output, and CloudTrail source options.

### Example
```toml
seed = 42 # Optional: deterministic generation.

[traffic]
start_time = "2025-12-01T00:00:00Z" # Optional simulated clock start.
time_scale = 100.0 # 100x faster than real time.

[output]
dir = "./out-test" # Output directory.

[output.files]
target_size_mb = 50 # Start a new file at ~50 MB.
flush_interval_ms = 1000 # Flush buffers at least every 1s.
max_age_seconds = 30 # Start a new file even if size not reached.

[output.format]
type = "jsonl" # jsonl (CloudTrail Records JSON) or parquet.
compression = "gzip" # jsonl only: writes .json.gz.

[source]
type = "cloudtrail"
curated = true # Load curated event weights.
actor_population_path = "./actors.parquet" # Required.
regions = ["us-east-1", "us-west-2", "eu-west-1"]
region_distribution = [0.6, 0.25, 0.15] # Weights aligned to regions.
```

### Fields
| Path | Type | Required | Default | Effect |
| --- | --- | --- | --- | --- |
| `seed` | int | no | random | Fixes RNG for repeatable output sequences. |
| `[traffic]` | table | yes | - | Simulated clock controls. |
| `traffic.start_time` | string | no | now | Shifts event timestamps; use for backfill windows. |
| `traffic.time_scale` | float | no | 1.0 | Increases/decreases how fast simulated time advances. |
| `[output]` | table | yes | - | Output sink configuration. |
| `output.dir` | string | yes | - | Output directory for generated files. |
| `[output.files]` | table | yes | - | File output controls. |
| `output.files.target_size_mb` | int | yes | - | Lower values create more, smaller files. |
| `output.files.flush_interval_ms` | int | no | 30000 | Shorter interval flushes buffers more often. |
| `output.files.max_age_seconds` | int | no | none | Forces periodic file rollover under low volume. |
| `[output.format]` | table | yes | - | Output format selection. |
| `output.format.type` | string | yes | - | `parquet` (structured) or `jsonl` (CloudTrail Records JSON). |
| `output.format.compression` | string | no | none | `jsonl` supports `gzip` to write `.json.gz`. |
| `[source]` | table | yes | - | Source configuration (CloudTrail). |
| `source.type` | string | yes | - | Must be `cloudtrail`. |
| `source.curated` | bool | yes | - | Enables curated event set and weights. |
| `source.actor_population_path` | string | yes | - | Points to the actors parquet; generation fails if missing. |
| `source.regions` | string[] | no | defaults | Region list for event emission. |
| `source.region_distribution` | float[] | no | none | Weights aligned with `source.regions`; must match length. |

### Region distribution (array form)
Provide weights aligned with the `regions` list:
```toml
regions = ["us-east-1", "us-west-2", "eu-west-1"]
region_distribution = [0.6, 0.25, 0.15]
```


## DuckDB validation
Run the analysis scripts against generated Parquet logs:
```bash
duckdb -c ".read scripts/duckdb/01_summary.sql"
duckdb -c ".read scripts/duckdb/02_sequences.sql"
duckdb -c ".read scripts/duckdb/03_errors.sql"
duckdb -c ".read scripts/duckdb/04_actor_chains.sql"
```
