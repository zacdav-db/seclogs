# Getting Started

## Prerequisites
- Rust toolchain (stable).

## Build
```
cargo check
```

## Generate logs
```
cargo run --bin seclog-cli -- gen --config examples/config.toml --output ./out-test
```

## Generate actor population (optional)
```
cargo run --bin seclog-cli -- actors --config examples/config.toml --output ./actor_population.parquet
```
