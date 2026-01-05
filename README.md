# Seclog

High-volume SIEM log generator with CloudTrail-style data.

## Documentation
- Rustdoc is the primary reference and is published to GitHub Pages.
- Build locally with `cargo doc --workspace --no-deps`.

## Quick start
```
cargo run --bin seclog-cli -- gen --config examples/config.toml --output ./out-test
```

## Common tasks
- Generate a reusable actor population:
  ```
  cargo run --bin seclog-cli -- actors --config examples/config.toml --output ./actors.parquet
  ```
- Use the population in `examples/config.toml` by setting `actor_population_path`.
