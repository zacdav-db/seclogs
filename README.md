# Seclog

High-volume SIEM log generator that creates realistic CloudTrail and Entra ID data from a reproducible actor population.

Use it to seed demo pipelines, load test SIEM analytics, or generate repeatable datasets with controlled volume, timing, and behavior.

Data realism comes from actor-driven generation: each actor has a role or service profile, session windows, timezones, and per-actor error rates. Events are selected with role-aware sequences and curated weights, then emitted over an accelerated or real-time clock. This produces traffic patterns that look like real users and service accounts, rather than uniform synthetic noise.

Multi-source runs reuse the same actor population, so identities overlap across systems while still allowing per-source selection ratios.

> [!NOTE]
> This project is under active development.

## Documentation
- Rustdoc is the primary reference and is published to GitHub Pages.
- Build locally with `cargo doc --no-deps --package seclog`.

## Getting started (end-to-end)
1. Generate an actor population (Parquet):
```bash
cargo run --bin seclog -- actors --config examples/actors.toml --output ./actors.parquet
```
2. Generate logs using that population (single or multiple sources):
```bash
cargo run --bin seclog -- gen --config examples/config.toml --output ./out-test
```

## CLI usage
### `seclog gen`
| Flag | Required | Default | Effect |
| --- | --- | --- | --- |
| `--config` | yes | - | Path to `config.toml`. |
| `--output` | no | from config | Overrides `output.dir`. |
| `--dry-run` | no | false | Prints the loaded config and exits. |
| `--max-events` | no | none | Stops after emitting this many events. |
| `--max-seconds` | no | none | Stops after this many **wall‑clock seconds** (e.g. `300` for 5 minutes). |
| `--metrics-interval-ms` | no | 1000 | Metrics print interval in milliseconds. |
| `--gen-workers` | no | 0 | Number of generator workers (actor‑driven mode forces 1). |
| `--writer-shards` | no | 0 | Number of writer shards (0 = auto). |

### `seclog actors`
| Flag | Required | Default | Effect |
| --- | --- | --- | --- |
| `--config` | yes | - | Path to `actors.toml`. |
| `--output` | yes | - | Output Parquet file for the actor population. |

## actors.toml reference (population generation)
`actors.toml` controls how the actor population is built and stored as Parquet.
It also defines per-source selectors that pick subsets of the shared population
for multi-source generation. Error rates are sampled per actor and applied at
generation time; error codes and messages come from built-in defaults per event.

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

# Explicit actors with fixed traits and behavior overrides.
[[population.actor]]
id = "human-mal-001"
kind = "human"
role = "admin"
events_per_hour = 42.0
error_rate = 0.18
timezone = "Europe/London"
active_start_hour = 8
active_hours = 10
weekend_active = false
user_name = "n.rogue"
account_id = "123456789012"
user_agents = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36", "curl/8.5.0"]
source_ips = ["203.0.113.45", "198.51.100.23"]
tags = ["malicious"]
event_bias = { "ConsoleLogin" = 3.0, "AssumeRole" = 2.0 }

[[population.selector]]
source_id = "cloudtrail"
human_ratio = 0.7
service_ratio = 1.0
seed = 7

[[population.selector]]
source_id = "entra_id"
human_ratio = 0.6
service_ratio = 0.2
seed = 7
```

### Fields
| Path | Type | Required | Default | Effect |
| --- | --- | --- | --- | --- |
| `seed` | int | no | random | Fixes RNG for repeatable populations. |
| `[[timezone_distribution]]` | table[] | no | none | Assigns actor local timezones; affects active windows and diurnal patterns. |
| `timezone_distribution.name` | string | yes | - | IANA timezone name used to compute offsets. |
| `timezone_distribution.weight` | float | yes | - | Higher increases share of actors in that timezone. |
| `[population]` | table | yes | - | Population parameters. |
| `population.actor_count` | int | no | 500 | Total actors; explicit entries count toward this number. |
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
| `population.actor` | table[] | no | none | Adds explicit actors with fixed traits and optional behavior biasing. |
| `population.selector` | table[] | no | none | Selects source-specific subsets from the shared population. |

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
| `population.service_profiles.name` | string | yes | Chooses the service behavior profile: `generic`, `ec2_reaper`, `datalake_bot`, `logs_shipper`, `metrics_collector`. |
| `population.service_profiles.weight` | float | yes | Higher weight increases share of that profile. |
| `population.service_profiles.events_per_hour` | float | no | Overrides `population.service_events_per_hour` for this profile. |
| `population.service_profiles.pattern` | string | no | Shapes activity over time (steady vs. diurnal vs. bursts). |

### Service profile meanings
- `generic`: Balanced mix of IAM, S3, EC2, and logs events.
- `ec2_reaper`: Focused on instance lifecycle cleanup (describe/stop/terminate).
- `datalake_bot`: Heavy S3 + KMS usage (put/get objects, encrypt/decrypt, data keys).
- `logs_shipper`: CloudWatch Logs activity (create streams, put log events).
- `metrics_collector`: CloudWatch Metrics activity (get/put metrics, list metrics).

### Explicit actor entries
Explicit actors are always included. If `population.actor_count` is smaller than the
explicit list size, Seclog keeps all explicit actors and skips generating additional ones.

| Path | Type | Required | Effect |
| --- | --- | --- | --- |
| `population.actor.id` | string | yes | Unique identifier for the explicit actor. |
| `population.actor.kind` | string | yes | `human` or `service`; controls session behavior and defaults. |
| `population.actor.role` | string | human | Required for humans: `admin`, `developer`, `readonly`, `auditor`. |
| `population.actor.service_profile` | string | service | Required for services: `generic`, `ec2_reaper`, `datalake_bot`, `logs_shipper`, `metrics_collector`. |
| `population.actor.service_pattern` | string | no | Optional service pacing (`constant`, `diurnal`, `bursty`). |
| `population.actor.events_per_hour` | float | yes | Baseline per‑actor throughput. |
| `population.actor.error_rate` | float | no | Overrides sampled error rate (0.0–1.0). |
| `population.actor.account_id` | string | no | Overrides the AWS account ID (12 digits). |
| `population.actor.user_name` | string | no | Overrides IAM username for human actors. |
| `population.actor.principal_id` | string | no | Overrides the principal ID. |
| `population.actor.arn` | string | no | Overrides the full ARN. |
| `population.actor.access_key_id` | string | no | Overrides the access key ID. |
| `population.actor.identity_type` | string | no | Overrides identity type (defaults to `IAMUser` / `AssumedRole`). |
| `population.actor.timezone` | string | no | IANA timezone name for activity windows; overrides distribution. |
| `population.actor.active_start_hour` | int | no | Local hour (0–23) when the actor becomes active. |
| `population.actor.active_hours` | int | no | Active window length in hours (1–24). |
| `population.actor.weekend_active` | bool | no | When false, the actor skips weekends. |
| `population.actor.user_agents` | string[] | no | Overrides the actor’s user‑agent pool. |
| `population.actor.source_ips` | string[] | no | Overrides the actor’s source IP pool. |
| `population.actor.tags` | string[] | no | Free‑form labels for downstream analytics. |
| `population.actor.event_bias` | map | no | Multiplies per-source event weights for this actor (e.g. `{ "ConsoleLogin" = 3.0 }`). |

### Selector entries
Selectors choose a deterministic subset of actors per source, allowing partial overlap
between systems while preserving identity consistency. If a source has no selector
entry, all actors are used.

| Path | Type | Required | Effect |
| --- | --- | --- | --- |
| `population.selector.source_id` | string | yes | Must match a `source.id` in `config.toml`. |
| `population.selector.human_ratio` | float | yes | Share of human actors included (0.0–1.0). |
| `population.selector.service_ratio` | float | yes | Share of service actors included (0.0–1.0). |
| `population.selector.seed` | int | no | Seeds the selection hash for repeatable overlap. |

### Error rate entries
| Path | Type | Required | Effect |
| --- | --- | --- | --- |
| `population.error_rate.min` | float | yes | Lower bound for sampled error rates. |
| `population.error_rate.max` | float | yes | Upper bound for sampled error rates. |
| `population.error_rate.distribution` | string | no | `uniform` spreads evenly; `normal` concentrates around mid-range. |

## config.toml reference (log generation)
`config.toml` controls generation, output, the shared actor population, and
multiple sources in a single run.

### Example
```toml
seed = 42 # Optional: deterministic generation.

[traffic]
start_time = "2025-12-01T00:00:00Z" # Optional simulated clock start.
time_scale = 100.0 # 100x faster than real time.

[output]
dir = "./out-test" # Output directory (sources use subdirs).

[output.files]
target_size_mb = 50 # Start a new file at ~50 MB.
max_age_seconds = 30 # Always rotate if this age is reached.

[population]
actors_config_path = "./actors.toml" # Required for selectors.
actor_population_path = "./actors.parquet" # Required for generation.

[[source]]
id = "cloudtrail"
type = "cloudtrail"
curated = true # Load curated event weights.
regions = ["us-east-1", "us-west-2", "eu-west-1"]
region_distribution = [0.6, 0.25, 0.15] # Weights aligned to regions.

[source.output.format]
type = "jsonl" # jsonl (CloudTrail Records JSON) or parquet.
compression = "gzip" # jsonl only: writes .json.gz.

[[source]]
id = "entra_id"
type = "entra_id"
tenant_id = "72f988bf-86f1-41af-91ab-2d7cd011db47"
tenant_domain = "contoso.onmicrosoft.com"
categories = ["signin", "audit"]
category_weights = [0.7, 0.3]

[source.output.format]
type = "parquet"
```

### Fields
| Path | Type | Required | Default | Effect |
| --- | --- | --- | --- | --- |
| `seed` | int | no | random | Fixes RNG for repeatable output sequences. |
| `[traffic]` | table | yes | - | Simulated clock controls. |
| `traffic.start_time` | string | no | now | Shifts event timestamps; use for backfill windows. |
| `traffic.time_scale` | float | no | 1.0 | Increases/decreases how fast simulated time advances. |
| `[output]` | table | yes | - | Output sink configuration. |
| `output.dir` | string | yes | - | Base output directory for generated files. |
| `[output.files]` | table | yes | - | File output controls. |
| `output.files.target_size_mb` | int | yes | - | Lower values create more, smaller files. |
| `output.files.max_age_seconds` | int | yes | - | Forces periodic file rollover under low volume. |
| `[population]` | table | yes | - | Shared actor population config. |
| `population.actors_config_path` | string | yes | - | Points to `actors.toml` for selectors. |
| `population.actor_population_path` | string | yes | - | Points to the actors parquet file. |
| `[[source]]` | table[] | yes | - | One or more sources to generate in a single run. |
| `source.id` | string | yes | - | Identifier referenced by population selectors. |
| `source.type` | string | yes | - | Source type (`cloudtrail`, `entra_id`). |
| `source.output.dir` | string | no | source.id | Subdirectory under `output.dir`. |
| `[source.output.format]` | table | yes | - | Output format selection per source. |
| `source.output.format.type` | string | yes | - | `parquet` (structured) or `jsonl` (CloudTrail Records JSON or JSONL). |
| `source.output.format.compression` | string | no | none | `jsonl` supports `gzip` to write `.json.gz`. |
| `source.curated` | bool | cloudtrail | - | Enables curated event set and weights. |
| `source.regions` | string[] | cloudtrail | defaults | Region list for event emission. |
| `source.region_distribution` | float[] | cloudtrail | none | Weights aligned with `source.regions`; must match length. |
| `source.tenant_id` | string | entra_id | - | Entra tenant GUID. |
| `source.tenant_domain` | string | entra_id | - | Entra tenant domain. |
| `source.categories` | string[] | entra_id | signin+audit | Log categories to emit (`signin`, `audit`). |
| `source.category_weights` | float[] | entra_id | none | Weights aligned with `source.categories`. |

### Region distribution (array form)
Provide weights aligned with the `regions` list:
```toml
regions = ["us-east-1", "us-west-2", "eu-west-1"]
region_distribution = [0.6, 0.25, 0.15]
```


## DuckDB validation
Run the analysis scripts against generated Parquet logs:
```bash
duckdb -c ".read scripts/duckdb/cloudtrail/parquet/01_summary.sql"
duckdb -c ".read scripts/duckdb/cloudtrail/parquet/02_sequences.sql"
duckdb -c ".read scripts/duckdb/cloudtrail/parquet/03_errors.sql"
duckdb -c ".read scripts/duckdb/cloudtrail/parquet/04_actor_chains.sql"
```
