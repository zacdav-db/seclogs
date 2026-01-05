# Seclog

High-volume SIEM log generator with CloudTrail-style data.

## Documentation
- Rustdoc is built by GitHub Actions and published to GitHub Pages.
- Supplementary notes live in `docs/`.

## Quick start
```
cargo run --bin seclog-cli -- gen --config examples/config.toml --output ./out-test
```
