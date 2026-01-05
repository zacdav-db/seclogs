# Configuration

The config file is TOML. See `examples/config.toml` for a working example.

## Top-level
- `seed`: Optional RNG seed.
- `traffic`: Volume control.
- `output`: Output directory and rotation.
- `source`: Single source config (CloudTrail).

## Traffic
```
[traffic]
mode = "realistic" # or "constant"
events_per_second = 50000.0

[traffic.curve]
type = "weekday_peak"
weekday_multiplier = 1.0
weekend_multiplier = 0.6
peak_hours_local = [9, 10, 11, 12, 13, 14, 15, 16]
peak_multiplier = 1.4

[[traffic.timezone_distribution]]
name = "America/Los_Angeles"
weight = 0.63
```

## Output
```
[output]
dir = "./out"

[output.rotation]
target_size_mb = 50
max_age_seconds = 10

[output.format]
type = "parquet" # or "jsonl"
compression = "zstd"
```

Rotation:
- `target_size_mb` controls the file size.
- `max_age_seconds` flushes any region buffer once it exceeds this age.

## CloudTrail source
```
[source]
type = "cloudtrail"
curated = true
actor_count = 800
service_ratio = 0.25
hot_actor_ratio = 0.12
hot_actor_share = 0.6
account_count = 1
regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
actor_population_path = "./actor_population.parquet"

[[source.custom_events]]
name = "ConsoleLogin"
weight = 1.0
```

Fields:
- `curated`: Use curated event catalog.
- `custom_events`: Override or add event weights.
- `actor_count`, `service_ratio`: Actor pool size and human/service split.
- `hot_actor_ratio`, `hot_actor_share`: Skew traffic to hot actors.
- `account_ids` or `account_count`: AWS account IDs.
- `actor_population_path`: Load actor population from Parquet.
- `error_rates`: Per-event error rates.
- `role_distribution`: Human role weights.
- `regions`: Explicit list of regions.
- `region_distribution`: Region weights.
