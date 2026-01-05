# Actor Populations

Actor populations can be persisted to Parquet and reused by sources.

## Generate
```
cargo run --bin seclog-cli -- actors --config examples/config.toml --output ./actor_population.parquet
```

## Use
Add to the source config:
```
actor_population_path = "./actor_population.parquet"
```

## Behavior
- Humans typically have multiple user agents and IPs.
- Services usually have one, sometimes two.
- A single session sticks to one user agent and IP.
