# Python API

Seclog's Python package wraps the Rust generator with a small, typed API. It is
intended for notebooks, tests, local data files, and Python pipelines that need
repeatable security log data without shelling out to the CLI.

The package emits independent CloudTrail, Databricks audit, and Okta System Log
events from one shared actor population. Each actor keeps the same identity
across sources, so cross-source activity is coherent without hand-authoring
every user and service account.

## Installation

Install the package from the repository root:

```bash
pip install -e .
```

For direct Rust extension development, `maturin` works as well:

```bash
maturin develop
```

Both commands build the native extension with the `python` Cargo feature.

## Quickstart

Generate normalized events in memory:

```python
import seclog

events = seclog.generate(max_events=500)
first_event = events[0]
```

Each generated event is a dictionary with two top-level keys:

- `envelope`: normalized seclog metadata such as source, actor, outcome, and time.
- `payload`: the source-native CloudTrail, Databricks audit, or Okta record.

Generate source-native payloads only:

```python
okta_rows = seclog.payloads(sources=["okta"], max_events=100)
```

Use `generate` when downstream code needs normalized envelope metadata. Use
`payloads` when loading raw records into source-specific tables.

## Generation Inputs

Python code and TOML configs are two equivalent ways to describe a run.

Use code when the population is part of the Python workflow:

```python
population = seclog.Population(
    size=1000,
    seed=7,
    timezones=[
        ("America/Los_Angeles", 0.45),
        ("Europe/London", 0.35),
        ("Asia/Singapore", 0.20),
    ],
)

events = seclog.generate(
    population=population,
    sources=["cloudtrail", "databricks_audit", "okta"],
    max_events=10_000,
)
```

Use TOML when the same config should be shared with the CLI:

```python
events = seclog.generate(
    config_path="examples/all_sources.toml",
    max_events=1000,
)

config = seclog.load_config("examples/all_sources.toml")
```

When `config`, `config_path`, or `config_toml` is set, that config is the source
of truth. Do not also pass `sources`, `population`, or source-specific keyword
overrides in the same call.

## Streaming

`seclog.stream` creates one persistent Rust generator. Generation starts when
the stream is iterated, so repeated batches continue from the same run instead
of restarting from the seed.

```python
events = seclog.stream(config_path="examples/all_sources.toml")

for event in events:
    handle(event)
```

Batch iteration is available for consumers that write in chunks:

```python
events = seclog.stream(config_path="examples/all_sources.toml")

for batch in events.batches(1000):
    write_batch(batch)
```

## Writing JSONL

Write APIs create files and are deliberately stricter than in-memory generation:
they require an explicit generation input and an explicit event limit. Pass one
of `population`, `config`, `config_path`, or `config_toml`, and pass
`max_events=N` for bounded writes. Use `max_events=None` only for an intentional
continuous write that runs until the source stream ends or the process stops.
Top-level write calls are blocking: they return after the requested events are
written, the configured stream is exhausted, or an error is raised.

Write normalized rows with `envelope` and `payload`:

```python
population = seclog.Population(size=1000, seed=42)

count = seclog.write_events_jsonl(
    "out/seclog/events.jsonl",
    population=population,
    sources=["cloudtrail", "databricks_audit", "okta"],
    max_events=50_000,
)
```

Write source-native payloads:

```python
population = seclog.Population(size=1000, seed=42)

payload_count = seclog.write_payloads_jsonl(
    "out/seclog/okta_payloads.jsonl",
    population=population,
    sources=["okta"],
    max_events=10_000,
)
```

Route source-native payloads to one file per source:

```python
seclog.sink_jsonl(
    {
        "cloudtrail": "out/seclog/cloudtrail.jsonl",
        "databricks_audit": "out/seclog/databricks_audit.jsonl",
        "okta": "out/seclog/okta_system_log.jsonl",
    },
    config_path="examples/all_sources.toml",
    max_events=50_000,
)
```

`write_jsonl` remains available as a lower-level helper when `payload_only`
needs to be selected dynamically, but application code should usually prefer
`write_events_jsonl` or `write_payloads_jsonl` because the output row shape is
clear from the function name.

## Identity Population

Names, emails, Okta user IDs, Databricks usernames, and AWS principals are
synthesized from the same population. The generated names and identity fields
follow the actor's location and timezone context.

Inspect the identities that a population will produce:

```python
population = seclog.Population(size=25, seed=42)
identities = seclog.identities(population)
```

Pin specific actors when a test or investigation needs a known account, while
letting seclog synthesize the rest:

```python
population = seclog.Population(
    size=250,
    explicit_actors=[
        seclog.ExplicitActor(
            id="human-admin-001",
            kind="human",
            role="admin",
            timezone="Europe/London",
            source_ips=["203.0.113.45"],
            tags=["investigation"],
            event_bias={"ConsoleLogin": 3.0, "AssumeRole": 2.0},
        )
    ],
)

events = seclog.generate(
    population=population,
    sources=["cloudtrail", "databricks_audit", "okta"],
    max_events=1000,
)
```

Explicit actors can define behavior, identifiers, or names. Omitted names and
platform identity fields are generated from the actor's location context.

## Advanced Config

Use `default_config` when code should build a full seclog config but still keep
common settings near the call site:

```python
config = seclog.default_config(
    sources=["okta", "databricks_audit"],
    population=seclog.Population(size=500, seed=11),
    source_overrides={
        "okta_system_log": {"baseline_events_per_actor": 4},
        "databricks_audit": {"workspace_id": "9876543210"},
    },
)

events = seclog.generate_from_config(config, max_events=1000)
```

`default_config` returns the same JSON-compatible config shape that the Rust
library deserializes.

## Current Scope

The Python package currently supports in-memory generation, persistent stream
iteration, and local JSONL sinks. Managed file output, Databricks volume
uploads, and Zerobus writes remain CLI capabilities. The Okta generator is
schema-faithful for the selected auth, session, and app-access events it emits,
but it is not a full implementation of Okta's event-type catalog.
