# Seclog

High-volume SIEM log generator that creates realistic source-native security log data from a reproducible actor population.

Use it to seed test pipelines, load test SIEM analytics, or generate repeatable datasets with controlled volume, timing, and behavior.

Data realism comes from actor-driven generation: each actor has a role or service profile, session windows, timezones, and per-actor error rates. Events are selected with role-aware sequences and curated weights, then emitted over an accelerated or real-time clock. This produces traffic patterns that look like real users and service accounts, rather than uniform synthetic noise.

> [!NOTE]
> This project is under active development.

## Documentation
- Rustdoc is the primary reference and is published to GitHub Pages.
- Build locally with `cargo doc --no-deps --package seclog`.
- Python binding UX is documented in `docs/python_bindings.md`.

## Getting started (end-to-end)
1. Generate an actor population (Parquet):
```bash
cargo run --bin seclog -- actors --config examples/actors.toml --output ./actors.parquet
```
2. Generate CloudTrail logs using that population:
```bash
cargo run --bin seclog -- gen --config examples/config.toml --output ./out-test
```

To generate Databricks audit rows from a shared identity registry:
```bash
cargo run --bin seclog -- gen --config examples/databricks_audit.toml --output ./out-databricks
```

To generate Okta System Log events from a shared identity registry:
```bash
cargo run --bin seclog -- gen --config examples/okta_system_log.toml --output ./out-okta
```

To generate CloudTrail, Databricks audit, and Okta System Log from one
synthesized actor population in a single run:
```bash
cargo run --bin seclog -- gen --config examples/all_sources.toml --max-events 100
```

To stream the same sources to Databricks Zerobus Ingest:
```bash
export DATABRICKS_CLIENT_ID="..."
export DATABRICKS_CLIENT_SECRET="..."
cargo run --features zerobus --bin seclog -- gen --config examples/all_sources_zerobus.toml --max-events 100
```

To upload source-native files to a Unity Catalog volume through the Databricks Files API:
```bash
export DATABRICKS_TOKEN="..."
cargo run --features databricks_volume --bin seclog -- gen --config examples/all_sources_volume.toml --max-events 100
```

## Python bindings
The Python package wraps the Rust library for in-memory generation with strong
defaults. By default it synthesizes one shared identity population and emits
independent CloudTrail, Databricks audit, and Okta System Log events from that
population.

Build the extension locally:
```bash
pip install -e .
```

Generate normalized events:
```python
import seclog

events = seclog.generate(max_events=500)
```

Generate source-native payloads only:
```python
okta_rows = seclog.payloads(sources=["okta"], max_events=100)
```

Use an existing TOML generator config instead of code:
```python
events = seclog.generate(
    config_path="examples/all_sources.toml",
    max_events=1000,
)
```

Run a persistent stream and route source-native payloads to per-source JSONL
destinations:
```python
seclog.sink_jsonl(
    {
        "cloudtrail": "out/python/cloudtrail.jsonl",
        "databricks_audit": "out/python/databricks_audit.jsonl",
        "okta": "out/python/okta_system_log.jsonl",
    },
    config_path="examples/all_sources.toml",
    max_events=None,
    events_per_second=250,
)
```

Write helpers require an explicit generation input such as `config_path` or
`population`; they will not silently start from the default population.

Customize the population without hand-authoring every identity:
```python
population = seclog.Population(
    size=1000,
    timezones=[
        ("America/Los_Angeles", 0.45),
        ("Europe/London", 0.35),
        ("Asia/Singapore", 0.20),
    ],
)

events = seclog.generate(population=population, max_events=10_000)
identities = seclog.identities(population)
```

See `docs/python_bindings.md` for the full UX, including explicit actor
overrides and JSONL writing.

## CLI usage
### `seclog gen`
| Flag | Required | Default | Effect |
| --- | --- | --- | --- |
| `--config` | yes | - | Path to `config.toml`. |
| `--output` | no | from config | Overrides file-output `output.dir`. Not valid for Zerobus or Databricks volume output. |
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

## Shared identity registry
Sources that need cross-system identity correlation can load an identity registry TOML.
The registry maps stable internal actor IDs to source-native identifiers such as email,
Okta user ID, Databricks username, and AWS principal identifiers. Scenario-specific
people and service accounts should live in registry data files rather than source code.

```toml
name = "example_identity_registry"

[[identity]]
actor_id = "user-001"
email = "amelia.chen@example.com.au"
employee_id = "E-000001"
display_name = "Amelia Chen"
role_persona = "Finance operations analyst"
department = "Business Operations"
home_location = "Sydney, NSW, Australia"
normal_countries_regions = ["Australia", "Australia/NSW"]
okta_user_id = "00u-example-user-001"
databricks_username = "amelia.chen@example.com.au"
service_account = false
tags = ["human"]

[[identity.aws_principals]]
account_id = "123456789012"
principal_id = "AIDAEXAMPLEUSER001"
arn = "arn:aws:iam::123456789012:user/amelia.chen"
access_key_id = "AKIAEXAMPLEUSER01"
```

## actors.toml reference (population generation)
`actors.toml` controls how the actor population is built and stored as Parquet.
Generated human actors get locale-aware display names, usernames, email
domains, home locations, and normal country/region baselines from
`timezone_distribution` or an explicit actor `timezone`. Exact IANA timezone
names are used before falling back to UTC offset, so `Australia/Perth` remains
an Australian population instead of being treated like another UTC+8 region.
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
account_id = "123456789012"
user_agents = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36", "curl/8.5.0"]
source_ips = ["203.0.113.45", "198.51.100.23"]
tags = ["malicious"]
event_bias = { "ConsoleLogin" = 3.0, "AssumeRole" = 2.0 }
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
| `population.actor.display_name` | string | no | Overrides the actor display name. Missing human names are generated from the actor timezone locale. |
| `population.actor.email` | string | no | Overrides actor email. Missing human emails use the actor username and locale email domain. |
| `population.actor.home_location` | string | no | Overrides the actor home location used by source generators. |
| `population.actor.normal_countries_regions` | string[] | no | Overrides normal country/region baselines used by source generators. |
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
| `population.actor.event_bias` | map | no | Multiplies CloudTrail event weights for this actor (e.g. `{ "ConsoleLogin" = 3.0 }`). |

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
max_age_seconds = 30 # Always rotate if this age is reached.

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
| `output.type` | string | no | file | Set to `zerobus` for Databricks Zerobus output or `databricks_volume` for Databricks Files API volume uploads; omit for file output. |
| `output.dir` | string | file only | - | Output directory for generated files. |
| `[output.files]` | table | file only | - | File output controls. |
| `output.files.target_size_mb` | int | file only | - | Lower values create more, smaller files. |
| `output.files.max_age_seconds` | int | file only | - | Forces periodic file rollover under low volume. |
| `[output.format]` | table | file only | - | Output format selection. |
| `output.format.type` | string | file only | - | `parquet` (structured) or `jsonl` (CloudTrail Records JSON). |
| `output.format.compression` | string | no | none | `jsonl` supports `gzip` to write `.json.gz`. |
| `output.workspace_url` | string | Zerobus/volume | - | Databricks workspace URL. |
| `output.volume_path` | string | volume only | - | UC volume landing directory, `/Volumes/<catalog>/<schema>/<volume>/<path>` or `dbfs:/Volumes/...`. |
| `output.token_env` | string | volume only | `DATABRICKS_TOKEN` | Environment variable containing the Databricks bearer token for Files API uploads. |
| `output.target_size_mb` | int | volume only | 50 | Uploads a new volume file when the buffered source partition reaches this uncompressed size; must be no more than 5120. |
| `output.max_age_seconds` | int | volume only | 30 | Uploads buffered volume files after this age under low volume. |
| `output.flush_interval_ms` | int | Zerobus/volume | 1000 | Periodic flush cadence for streaming or remote sinks. |
| `output.compression` | string | volume only | none | `gzip` writes `.json.gz` files to the volume. |
| `output.overwrite` | bool | volume only | false | Files API overwrite flag for generated file names. |
| `[source]` | table | yes | - | Source configuration. |
| `source.type` | string | yes | - | Source generator: `cloudtrail`, `databricks_audit`, `okta`, or `multi`. |
| `source.curated` | bool | yes | - | Enables curated event set and weights. |
| `source.actor_population_path` | string | no | - | For CloudTrail Parquet-backed generation, points to the actors parquet. |
| `source.identity_registry_path` | string | no | - | For CloudTrail registry-backed generation, uses the shared identity registry instead of an actor Parquet file. |
| `source.regions` | string[] | no | defaults | Region list for event emission. |
| `source.region_distribution` | float[] | no | none | Weights aligned with `source.regions`; must match length. |

### Databricks audit source
Use `source.type = "databricks_audit"` to emit payloads shaped like
Databricks `system.access.audit` rows. The source loads a shared identity
registry, generates optional baseline activity for each identity, and can inject
deterministic audit events for a scenario.

This source is intentionally limited today. It preserves the real
`system.access.audit` row shape and supports deterministic baseline rows plus
explicit injected events, but it is not yet a broad Databricks audit catalog
covering every service/action family.

```toml
[source]
type = "databricks_audit"
identity_registry_path = "./examples/identity_registry.toml"
account_id = "example-account-id"
workspace_id = "1234567890"
baseline_events_per_actor = 2

[source.baseline_source_ips]
user-001 = ["198.51.100.10"]

[[source.event]]
actor_id = "user-001"
offset_seconds = 10
source_ip_address = "203.0.113.45"
service_name = "accounts"
action_name = "IpAccessDenied"
request_params = { login_type = "browser" }
response_status_code = 403
response_error_message = "Current IP is not allowed"
```

Databricks audit payloads include `event_time`, `source_ip_address`,
`user_identity.email`, `service_name`, `action_name`, `request_params`,
`response.status_code`, and `response.error_message`. The generator follows the
observed `system.access.audit` schema: `request_params` is a `map<string,string>`,
`response` is `struct<status_code:int,error_message:string,result:string>`, and
`identity_metadata` includes `run_by`, `run_as`, `acting_resource`,
`run_by_display_name`, and `run_as_display_name`.

### Okta System Log source
Use `source.type = "okta"` to emit payloads shaped like Okta System Log
`LogEvent` records. The alias `okta_system_log` is also accepted. The source
loads the shared identity registry, maps generated actors to Okta user/client
IDs, emits deterministic baseline auth/session/app-access activity, and can
inject explicit System Log events.

This source is intentionally limited today. It preserves the raw Okta
System Log landing shape and selected nested objects, including `actor`,
`authenticationContext`, `client`, `device`, `debugContext`, `outcome`,
`request`, `securityContext`, `target`, and `transaction`, but it is not a
full implementation of the Okta event-type catalog.

```toml
[source]
type = "okta"
identity_registry_path = "./examples/identity_registry.toml"
org_id = "okta-example-org"
baseline_events_per_actor = 2

[source.baseline_source_ips]
user-001 = ["198.51.100.10"]

[[source.event]]
actor_id = "user-001"
offset_seconds = 10
event_type = "app.generic.unauth_app_access_attempt"
display_message = "User attempted unauthorized access to app"
legacy_event_type = "app.generic.unauth_app_access_attempt"
outcome_result = "FAILURE"
severity = "WARN"
source_ip_address = "203.0.113.45"
source_geo_country = "Example Country"
source_geo_city = "Example City"

[[source.event.target]]
id = "0oa-example-operations"
type = "AppInstance"
alternate_id = "Operations Portal"
display_name = "Operations Portal"
detail_entry = { signOnModeType = "SAML_2_0" }
```

Okta payloads use Okta camelCase field names plus Okta device posture field
names such as `os_platform`, `disk_encryption_type`, and
`secure_hardware_present`. `client.ipAddress` is mirrored to
`request.ipChain[0].ip`, `authenticationContext.rootSessionId` mirrors
`externalSessionId`, `debugContext.debugData` remains a dynamic JSON object,
and `target` entries carry typed `type` values such as `AppInstance` and
`AppUser`; consumers should search targets by type rather than array position.

### Multi-source generation
Use `source.type = "multi"` when one run should emit independent log sources
from the same actor population. Each child source remains source-native. For
file output, `source.outputs` routes events by normalized source name.

```toml
[source]
type = "multi"
population_config_path = "./examples/actors.toml"

[source.outputs.cloudtrail]
dir = "./out-all-sources/cloudtrail"

[source.outputs.cloudtrail.files]
target_size_mb = 50
max_age_seconds = 10

[source.outputs.cloudtrail.format]
type = "jsonl"
compression = "gzip"

[[source.sources]]
type = "cloudtrail"
curated = true

[[source.sources]]
type = "databricks_audit"
account_id = "example-account-id"
workspace_id = "1234567890"

[[source.sources]]
type = "okta"
org_id = "okta-example-org"
```

`population_config_path` points to the same population config used by
`seclog actors`. Seclog synthesizes a shared identity registry in memory, so
CloudTrail, Databricks audit, and Okta events share the same realistic actor
population without requiring one hand-written registry entry per user. Use
`identity_registry_path` instead when you need a fully curated registry.

The built-in route keys are `cloudtrail`, `databricks_audit`, and
`okta_system_log`. If a file route is not listed under `source.outputs`, the
top-level file `[output]` sink is used as a fallback.

### Databricks Zerobus output
Use `[output] type = "zerobus"` to stream generated rows directly into
pre-created Unity Catalog Delta tables through Databricks Zerobus Ingest. This
is an output sink, not a source; generated events remain source-native and are
routed by `event.envelope.source`.

```toml
[output]
type = "zerobus"
workspace_url = "https://dbc-example.cloud.databricks.com"
endpoint = "https://1234567890123456.zerobus.us-west-2.cloud.databricks.com"
client_id_env = "DATABRICKS_CLIENT_ID"
client_secret_env = "DATABRICKS_CLIENT_SECRET"
batch_size = 500
max_inflight_requests = 10000
flush_interval_ms = 1000

[output.tables]
cloudtrail = "main.seclog.cloudtrail_events"
databricks_audit = "main.seclog.databricks_audit_events"
okta_system_log = "main.seclog.okta_system_log_events"
actor_population = "main.seclog.actor_population"
```

Build with the optional feature:
```bash
cargo run --features zerobus --bin seclog -- gen --config examples/all_sources_zerobus.toml
```

Secrets are read from the configured environment variables and are never stored
in TOML. Target tables must already exist as managed Delta tables in the same
region as the Zerobus endpoint. The service principal needs `USE CATALOG`,
`USE SCHEMA`, `SELECT`, and `MODIFY` on the destination objects. A table DDL
template is available at `scripts/databricks/zerobus/create_seclog_tables.sql`.

Each destination table uses the common seclog row shape:
`time`, `event_time`, `event_date`, `event_ts_ms`, `source`, `event_type`,
`actor_id`, `actor_kind`, `actor_name`, `target_id`, `target_kind`,
`target_name`, `outcome`, `ip`, `user_agent`, `session_id`, `tenant_id`,
`envelope_json`, `payload_json`, `run_id`, and `generated_at`.
`time` must be a target table `TIMESTAMP` column and is emitted on the JSON path
as epoch microseconds for Zerobus. `payload_json` preserves the exact
CloudTrail, Databricks audit, or Okta payload. When an `actor_population` table
route is present and the source configuration uses an `identity_registry_path`,
`population_config_path`, or inline `population_config`, `seclog gen` writes the
identity population to that table before event generation. The actor population
table uses `time`,
`registry_name`, `actor_id`, `actor_kind`, identity fields,
`normal_countries_regions_json`, `tags_json`, `aws_principals_json`,
`identity_json`, `run_id`, and `generated_at`.

### Databricks volume output
Use `[output] type = "databricks_volume"` to upload rotated source-native JSON
files directly to a Unity Catalog volume through the Databricks Files API. This
is an output sink, not a source or table writer. It writes one file stream per
`event.envelope.source`, partitioned under the configured volume directory:
`source=<source>/tenant_id=<tenant>/region=<region>/...json[.gz]`.

```toml
[output]
type = "databricks_volume"
workspace_url = "https://dbc-example.cloud.databricks.com"
volume_path = "/Volumes/main/seclog/raw/seclog"
token_env = "DATABRICKS_TOKEN"
target_size_mb = 50
max_age_seconds = 30
flush_interval_ms = 1000
compression = "gzip"
overwrite = false
```

Build with the optional feature:
```bash
cargo run --features databricks_volume --bin seclog -- gen --config examples/all_sources_volume.toml
```

The Files API upload path sends raw bytes with `PUT /api/2.0/fs/files{file_path}`;
`file_path` must be an absolute UC volume path such as
`/Volumes/<catalog>/<schema>/<volume>/<path>`. `dbfs:/Volumes/...` is accepted
in config and normalized before upload. The writer enforces the Files API 5 GiB
upload limit for `target_size_mb` and calls the Files API directory endpoint to
ensure the generated partition directory exists.

Secrets are read from the configured token environment variable and are never
stored in TOML. The caller needs `USE CATALOG`, `USE SCHEMA`, `READ VOLUME`,
and `WRITE VOLUME` on the destination volume. The sink currently writes
CloudTrail-style `{"Records":[...]}` JSON bundles containing the exact
source-native payload for CloudTrail, Databricks audit, and Okta events;
optional gzip compression writes `.json.gz` files.

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
