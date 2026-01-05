# Seclog

High-volume SIEM log generator with CloudTrail-style data.

## Documentation
- Rustdoc is the primary reference and is published to GitHub Pages.
- Build locally with `cargo doc --workspace --no-deps`.

## Quick start
```
cargo run --bin seclog-cli -- actors --config examples/actors.toml --output ./actors.parquet
cargo run --bin seclog-cli -- gen --config examples/config.toml --output ./out-test
```

## Common tasks
- Generate a reusable actor population (stored as Parquet):
  ```
  cargo run --bin seclog-cli -- actors --config examples/actors.toml --output ./actors.parquet
  ```
- Generate CloudTrail logs using the population:
  ```
  cargo run --bin seclog-cli -- gen --config examples/config.toml --output ./out-test
  ```
- Ensure `actor_population_path` in `examples/config.toml` points at the Parquet file.

## DuckDB validation
Run the analysis scripts against generated Parquet logs:
```
duckdb -c ".read scripts/duckdb/01_summary.sql"
duckdb -c ".read scripts/duckdb/02_sequences.sql"
duckdb -c ".read scripts/duckdb/03_errors.sql"
duckdb -c ".read scripts/duckdb/04_actor_chains.sql"
```
