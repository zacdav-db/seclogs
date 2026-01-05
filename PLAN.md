# SIEM Log Generator Plan

## Goals
- Generate high volumes of logs (up to GB/s in some cases).
- Support size-based file rotation (e.g., ~100MB per file).
- Provide two traffic modes: constant flow and realistic flow.
- Start with CloudTrail as the initial source; extend to Okta/Entra later.
- Output formats: JSONL for text and Parquet preferred when possible.
- Use nested structs in Parquet; JSONL mirrors nested structure.
- Default to global organization behavior across multiple timezones.
- Align with a Databricks demo pipeline: generate data into a virtual data
  lake (storage target to be decided later).

## Scope and Requirements
- Language: Rust.
- Sources (v1): CloudTrail curated event catalog with custom override list.
- Formats (v1): JSONL and Parquet.
- Rotation: size-based with configurable target size.
- Volume control:
  - Constant flow: fixed events/sec or bytes/sec.
  - Realistic flow: weekday/weekend and peak-time curves; global org default.
- Large data handling: streaming generation, bounded buffers, backpressure.
- Determinism: seed-based reproducibility.

## Architecture Overview
### Core Components
- **Generator Engine**
  - Produces events from source modules.
  - Supports multiple workers with independent RNG streams.
  - Applies traffic mode (constant vs realistic) to event rate.
- **Source Modules**
  - CloudTrail module with event templates and weighted mixes.
  - Curated catalog with custom list override.
- **Output Pipeline**
  - Streaming writers for JSONL and Parquet.
  - Size-based rotation and flush controls.
- **Config and CLI**
  - Config-driven behavior via TOML/YAML.
  - CLI for running generation jobs and selecting outputs.

### Data Model
- **Common Event Envelope**
  - timestamp, source, event_type, actor, target, outcome
  - geo, ip, user_agent, session_id, tenant_id
  - raw payload or source-specific nested fields
- **Source-Specific Payloads**
  - CloudTrail fields: region, service, request_parameters,
    response_elements, error_code, error_message, account_id, etc.
- **Schema Versioning**
  - Include a schema version field in the envelope for evolution.

## CloudTrail Strategy
- Curated list of common events with weights (e.g., ConsoleLogin,
  AssumeRole, RunInstances, PutObject, DeleteBucket).
- Custom override list for user-defined event types and weights.
- Event templates support realistic field combinations and sequences.

## Traffic Modes
- **Constant Flow**
  - Fixed events/sec or bytes/sec.
  - No time-of-day variation.
- **Realistic Flow**
  - Global default with multi-timezone weighting.
  - Weekday/weekend deltas, peak hours, and optional bursts.
  - Configurable timezone distribution.

## Output and Rotation
- JSONL: primary text output, one event per line.
- Parquet: preferred binary output with nested structs.
- Rotation: target file size (e.g., 100MB) with dynamic frequency.
- Optional compression per format (configurable).

## Performance Plan
- Chunked generation with bounded queues.
- Streaming writes with backpressure.
- Minimal per-event allocation; reuse buffers where possible.
- Metrics for throughput and latency (optional in v1).

## Testing and Validation
- Deterministic runs with fixed seeds.
- Schema validation for JSONL and Parquet.
- Statistical sanity checks (event mix ratios, volume curves).
- Benchmarks for throughput (events/sec and bytes/sec).

## Milestones
1) Project scaffolding + config + CLI skeleton.
2) CloudTrail generator with curated catalog and JSONL output.
3) Size-based rotation and Parquet writer with nested schema.
4) Realistic traffic mode with global timezone logic.
5) Performance tuning, benchmarks, and validation checks.
