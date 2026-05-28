# Python Bindings UX

The Python package exposes the Rust generator through a small native extension
and a usability-focused wrapper. The default path generates a shared actor
population once and emits independent CloudTrail, Databricks audit, and Okta
System Log events from that same population.

## Install For Local Development

```bash
pip install -e .
```

or:

```bash
maturin develop
```

Both commands build the Rust extension with the `python` Cargo feature.

## Generate In Memory With Defaults

```python
import seclog

events = seclog.generate(max_events=500)
```

Each event is a dictionary with:

- `envelope`: normalized seclog metadata.
- `payload`: the source-native CloudTrail, Databricks audit, or Okta payload.

## Generate Source-Native Payloads

```python
okta_rows = seclog.payloads(sources=["okta"], max_events=100)
```

Use `payloads` when loading raw records into source-specific tables. Use
`generate` when downstream code needs normalized envelope metadata.

## Use A TOML Config

Every generation entry point accepts an existing seclog TOML config as either a
path or a string.

```python
events = seclog.generate(
    config_path="examples/all_sources.toml",
    max_events=1000,
)

config = seclog.load_config("examples/all_sources.toml")
```

When `config_path` or `config_toml` is set, the TOML file is the source of
truth. Do not also pass code-level source or population overrides.

## Stream Continuously

`seclog.stream` keeps one Rust generator alive and advances it event by event.
Use this for long-running jobs so generation does not restart from the same seed
on every batch.

```python
events = seclog.stream(config_path="examples/all_sources.toml")

for event in events:
    handle(event)
```

For batch consumers:

```python
events = seclog.stream(config_path="examples/all_sources.toml")

for batch in events.batches(1000):
    write_batch(batch)
```

## Sink To JSONL Destinations

Write APIs intentionally do not start from an implicit default generation. Pass
one explicit input: `population`, `config`, `config_path`, or `config_toml`.
Also pass `max_events`; use `max_events=None` only when you want the write to
continue until the stream ends or the process is stopped.

Write one continuous stream to a single destination:

```python
seclog.sink_jsonl(
    "out/seclog/events.jsonl",
    config_path="examples/all_sources.toml",
    max_events=50_000,
    payload_only=False,
)
```

Or route source-native payloads to one destination per source:

```python
seclog.sink_jsonl(
    {
        "cloudtrail": "out/seclog/cloudtrail.jsonl",
        "databricks_audit": "out/seclog/databricks_audit.jsonl",
        "okta": "out/seclog/okta_system_log.jsonl",
    },
    config_path="examples/all_sources.toml",
    max_events=None,
    events_per_second=250,
)
```

`max_events=None` runs until the configured source stream is exhausted or the
process is stopped. Some configured sources are finite; for example selected
Okta and Databricks audit baselines drain after their scheduled events are
emitted.

## Customize The Shared Population

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

events = seclog.generate(population=population, max_events=10_000)
```

Names, emails, Okta user IDs, Databricks usernames, and AWS principals are
synthesized from the same population, so cross-source activity remains
consistent without hand-authoring identities one at a time.

## Pin A Few Actors, Synthesize The Rest

```python
population = seclog.Population(
    size=250,
    explicit_actors=[
        seclog.ExplicitActor(
            id="human-investigate-001",
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
    sources=["cloudtrail", "databricks_audit", "okta"],
    population=population,
    max_events=1000,
)
```

Explicit actors can define behavior, identifiers, or names. Omitted names and
platform identity fields are generated from the actor's location context.

## Get The Identity Population

```python
identities = seclog.identities(seclog.Population(size=25))
```

This returns the shared registry entries that the Rust generators will resolve
across source payloads.

## Write JSONL

```python
population = seclog.Population(
    size=1000,
    seed=42,
    timezones=[
        ("America/Los_Angeles", 0.45),
        ("Europe/London", 0.35),
        ("Asia/Singapore", 0.20),
    ],
)

count = seclog.write_events_jsonl(
    "out/seclog/events.jsonl",
    population=population,
    sources=["cloudtrail", "databricks_audit", "okta"],
    max_events=50_000,
)

payload_count = seclog.write_payloads_jsonl(
    "out/seclog/okta_payloads.jsonl",
    population=population,
    sources=["okta"],
    max_events=10_000,
)
```

`write_events_jsonl` writes normalized rows with `envelope` and `payload`.
`write_payloads_jsonl` writes only the source-native payload. `write_jsonl`
remains available as a lower-level helper when `payload_only` needs to be
selected dynamically, but it follows the same explicit-input rule.

## Advanced Config Escape Hatch

```python
config = seclog.default_config(
    sources=["okta", "databricks_audit"],
    source_overrides={
        "okta_system_log": {"baseline_events_per_actor": 4},
        "databricks_audit": {"workspace_id": "9876543210"},
    },
)

events = seclog.generate_from_config(config, max_events=1000)
```

`default_config` returns the same JSON-compatible config shape that the Rust
library deserializes. The wrapper keeps common settings at the top level while
still allowing source-specific overrides where needed.

## Scope

The bindings currently expose in-memory generation, persistent stream
iteration, and local JSONL sinks. Managed file output, Databricks volume
uploads, and Zerobus remain CLI capabilities. The Okta generator is
schema-faithful for the selected auth/session/app-access events it emits, but
it is not a full implementation of Okta's event-type catalog.
