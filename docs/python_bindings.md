# Python API

Seclog's Python package wraps the Rust generator with a small, typed API for
notebooks, tests, local data files, and Python pipelines.

The default streaming workflow is:

1. Define the population or load a TOML config.
2. Create a stream.
3. Attach explicit sinks.
4. Start the stream.

Generation begins when `start()` is called. `start()` is blocking: it returns
after `max_events` is reached, the configured source stream is exhausted, or an
error is raised.

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

Install Databricks sink dependencies when Python streams should write to
Zerobus or Unity Catalog volumes:

```bash
pip install -e ".[databricks]"
```

## Stream To Sinks

Use an existing seclog TOML config when the same setup should be shared with the
CLI:

```python
import seclog

result = (
    seclog.stream(config_path="examples/all_sources.toml")
    .route(
        cloudtrail=seclog.jsonl("out/seclog/cloudtrail.jsonl"),
        databricks_audit=seclog.jsonl("out/seclog/databricks_audit.jsonl"),
        okta=seclog.jsonl("out/seclog/okta_system_log.jsonl"),
    )
    .start(max_events=50_000, progress=True)
)

print(result.events)
```

That example starts one generator from `examples/all_sources.toml`, routes each
source-native payload to the matching JSONL file, prints progress while it
runs, and returns a `StreamResult` when the write finishes.

For continuous generation, pass `max_events=None`. The call still blocks; stop
the process to end the stream.

Use code when the population is owned by the Python workflow:

```python
import seclog

population = seclog.Population(
    size=1000,
    seed=42,
    timezones=[
        ("America/Los_Angeles", 0.45),
        ("Europe/London", 0.35),
        ("Asia/Singapore", 0.20),
    ],
)

result = (
    seclog.stream(
        population=population,
        sources=["cloudtrail", "databricks_audit", "okta"],
    )
    .route(
        cloudtrail=seclog.jsonl("out/seclog/cloudtrail.jsonl"),
        databricks_audit=seclog.jsonl("out/seclog/databricks_audit.jsonl"),
        okta=seclog.jsonl("out/seclog/okta_system_log.jsonl"),
    )
    .start(max_events=50_000, progress=True)
)
```

Use a single sink path when only one source is generated:

```python
population = seclog.Population(size=1000, seed=42)

result = (
    seclog.stream(population=population, sources=["okta"])
    .to_jsonl("out/seclog/okta_system_log.jsonl")
    .start(max_events=10_000, progress=True)
)
```

## Sink Records

`to_jsonl(...)` writes source-native records by default, such as raw Okta
System Log objects or CloudTrail records.

Pass `record="event"` when the file should contain normalized seclog events
with two top-level keys:

- `envelope`: normalized metadata such as source, actor, outcome, and time.
- `payload`: the source-native record.

```python
population = seclog.Population(size=1000, seed=42)

result = (
    seclog.stream(population=population)
    .to_jsonl("out/seclog/events.jsonl", record="event")
    .start(max_events=10_000)
)
```

Multiple sinks fan out the same generated stream. This writes source-native
payloads to per-source files and also writes one normalized event file:

```python
population = seclog.Population(size=1000, seed=42)

result = (
    seclog.stream(
        population=population,
        sources=["cloudtrail", "databricks_audit", "okta"],
    )
    .route(
        cloudtrail=seclog.jsonl("out/seclog/cloudtrail.jsonl"),
        databricks_audit=seclog.jsonl("out/seclog/databricks_audit.jsonl"),
        okta=seclog.jsonl("out/seclog/okta_system_log.jsonl"),
    )
    .to_jsonl("out/seclog/events.jsonl", record="event")
    .start(max_events=10_000, progress=True)
)
```

`route(...)` maps each source to one sink or a list of sinks. A later
`to_jsonl(...)` call can still attach a sink that receives every source.

## Route Map

Use `route(...)` when different sources should go to different sink types. This
example sends Okta System Log rows to Zerobus and Databricks audit rows to both
local JSONL and a Unity Catalog volume:

```python
from databricks.sdk import WorkspaceClient
import seclog

workspace_client = WorkspaceClient()
population = seclog.Population(size=1000, seed=42)

result = (
    seclog.stream(
        population=population,
        sources=["okta", "databricks_audit"],
    )
    .route(
        okta=seclog.zerobus(
            "lakewatch.bronze.okta_system_logs_unmapped",
            workspace_client=workspace_client,
        ),
        databricks_audit=[
            seclog.jsonl("out/seclog/databricks_audit.jsonl"),
            seclog.volume(
                "/Volumes/lakewatch/bronze/raw/seclog",
                workspace_client=workspace_client,
            ),
        ],
    )
    .start(max_events=None, progress=True)
)
```

Each key is a source route. Each value is either one sink or a list of sinks. If
the stream emits a source that no sink handles, `start()` raises a deterministic
error instead of silently dropping events.

`zerobus(...)` writes the common seclog row shape with `time`, envelope
columns, `envelope_json`, and `payload_json`. It infers the Zerobus endpoint
from the Databricks SDK workspace client by checking SDK config, `/config`, and
the account workspace-details endpoint; pass `region=` only when those
endpoints are unavailable. `volume(...)` writes source-native JSONL files
directly below the configured volume path using
`<file_prefix>-<source>-000000.jsonl` file names.

## Progress

`progress=True` renders an updating terminal view on stderr. In non-interactive
output, such as notebooks and CI logs, it writes one readable block per
interval.

```text
seclog progress | running | total=37,122 | +3,734 | current=3,734.3/s | avg=3,711.8/s | elapsed=00:10
  sources:
    okta_system_log | total=37,122 | +3,734 | current=3,734.3/s | avg=3,711.8/s
  sinks:
    okta_system_log -> zerobus main.seclog.okta_system_log_events | total=37,122 | +3,734 | current=3,734.3/s | avg=3,711.8/s
```

Pass a callback when progress should be handled by application code:

```python
def report(snapshot: seclog.ProgressSnapshot) -> None:
    for source, counter in snapshot.sources.items():
        print(source, counter.events, counter.events_per_second)


population = seclog.Population(size=1000, seed=42)

result = (
    seclog.stream(population=population, sources=["okta"])
    .to_jsonl("out/seclog/okta_system_log.jsonl")
    .start(max_events=100_000, progress=report)
)
```

The callback receives a `ProgressSnapshot` with total and interval event counts,
overall rates, `sources`, `sinks`, and a `finished` flag on the final snapshot.

## In-Memory Generation

Use `generate` for small in-memory samples:

```python
events = seclog.generate(max_events=500)
first_event = events[0]
```

Use `payloads` when only source-native records are needed:

```python
okta_rows = seclog.payloads(sources=["okta"], max_events=100)
```

These functions are for finite samples. For files and long-running generation,
prefer `stream(...).to_jsonl(...).start(...)`.

## Config Inputs

Python code and TOML configs are alternative ways to describe a run. When
`config`, `config_path`, or `config_toml` is set, that config is the source of
truth. Do not also pass `sources`, `population`, or source-specific keyword
overrides in the same call.

To inspect a TOML config from Python:

```python
config = seclog.load_config("examples/all_sources.toml")
```

To build a config in Python and reuse it:

```python
population = seclog.Population(size=500, seed=11)
config = seclog.default_config(
    sources=["okta", "databricks_audit"],
    population=population,
    source_overrides={
        "okta_system_log": {"baseline_events_per_actor": 4},
        "databricks_audit": {"workspace_id": "9876543210"},
    },
)
result = (
    seclog.stream(config=config)
    .route(
        okta=seclog.jsonl("out/seclog/okta_system_log.jsonl"),
        databricks_audit=seclog.jsonl("out/seclog/databricks_audit.jsonl"),
    )
    .start(max_events=10_000, progress=True)
)
```

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
result = (
    seclog.stream(
        population=population,
        sources=["cloudtrail", "databricks_audit", "okta"],
    )
    .route(
        cloudtrail=seclog.jsonl("out/seclog/cloudtrail.jsonl"),
        databricks_audit=seclog.jsonl("out/seclog/databricks_audit.jsonl"),
        okta=seclog.jsonl("out/seclog/okta_system_log.jsonl"),
    )
    .start(max_events=1000)
)
```

Explicit actors can define behavior, identifiers, or names. Omitted names and
platform identity fields are generated from the actor's location context.

## Compatibility Helpers

The older `write_jsonl`, `write_events_jsonl`, `write_payloads_jsonl`, and
`sink_jsonl` functions remain available. They are thin wrappers around the
streaming sink implementation, but new application code should prefer the
explicit stream form:

```python
result = (
    seclog.stream(population=seclog.Population(size=1000), sources=["okta"])
    .to_jsonl("out/seclog/okta_system_log.jsonl")
    .start(max_events=10_000)
)
```

## Current Scope

The Python package currently supports in-memory generation, persistent stream
iteration, local JSONL sinks, Databricks Files API volume sinks, and Zerobus
sinks. Managed rotating file output remains a CLI capability. The Okta generator
is schema-faithful for the selected auth, session, and app-access events it
emits, but it is not a full implementation of Okta's event-type catalog.
