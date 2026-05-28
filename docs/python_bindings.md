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

## Stream To Sinks

Use an existing seclog TOML config when the same setup should be shared with the
CLI:

```python
import seclog

result = (
    seclog.stream(config_path="examples/all_sources.toml")
    .to(
        seclog.JsonlSink.payloads(
            {
                "cloudtrail": "out/seclog/cloudtrail.jsonl",
                "databricks_audit": "out/seclog/databricks_audit.jsonl",
                "okta": "out/seclog/okta_system_log.jsonl",
            }
        )
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
    .to(
        seclog.JsonlSink.payloads(
            {
                "cloudtrail": "out/seclog/cloudtrail.jsonl",
                "databricks_audit": "out/seclog/databricks_audit.jsonl",
                "okta": "out/seclog/okta_system_log.jsonl",
            }
        )
    )
    .start(max_events=50_000, progress=True)
)
```

Use a single sink path when only one source is generated:

```python
population = seclog.Population(size=1000, seed=42)

result = (
    seclog.stream(population=population, sources=["okta"])
    .to(seclog.JsonlSink.payloads("out/seclog/okta_system_log.jsonl"))
    .start(max_events=10_000, progress=True)
)
```

## Sink Records

`JsonlSink.payloads(...)` writes source-native records, such as raw Okta System
Log objects or CloudTrail records.

`JsonlSink.events(...)` writes normalized seclog events with two top-level keys:

- `envelope`: normalized metadata such as source, actor, outcome, and time.
- `payload`: the source-native record.

```python
population = seclog.Population(size=1000, seed=42)

result = (
    seclog.stream(population=population)
    .to(seclog.JsonlSink.events("out/seclog/events.jsonl"))
    .start(max_events=10_000)
)
```

Multiple sinks fan out the same generated stream:

```python
population = seclog.Population(size=1000, seed=42)

result = (
    seclog.stream(population=population, sources=["okta"])
    .to(
        seclog.JsonlSink.payloads("out/seclog/okta_payloads.jsonl"),
        seclog.JsonlSink.events("out/seclog/okta_events.jsonl"),
    )
    .start(max_events=10_000, progress=True)
)
```

## Progress

`progress=True` renders an updating terminal view on stderr. In non-interactive
output, such as CI logs, it falls back to one plain text line per interval.

```text
seclog running | 37,122 events | 3,711.8/s avg | 3,734.3/s current | 00:10 elapsed
sources
  name                                      events       avg/s   current/s
  okta_system_log                           37,122     3,711.8     3,734.3
sinks
  name                                      events       avg/s   current/s
  out/seclog/okta_system_log.jsonl          37,122     3,711.8     3,734.3
```

Pass a callback when progress should be handled by application code:

```python
def report(snapshot: seclog.ProgressSnapshot) -> None:
    for source, counter in snapshot.sources.items():
        print(source, counter.events, counter.events_per_second)


population = seclog.Population(size=1000, seed=42)

result = (
    seclog.stream(population=population, sources=["okta"])
    .to(seclog.JsonlSink.payloads("out/seclog/okta_system_log.jsonl"))
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
prefer `stream(...).to(...).start(...)`.

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
    .to(
        seclog.JsonlSink.payloads(
            {
                "okta": "out/seclog/okta_system_log.jsonl",
                "databricks_audit": "out/seclog/databricks_audit.jsonl",
            }
        )
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
    .to(
        seclog.JsonlSink.payloads(
            {
                "cloudtrail": "out/seclog/cloudtrail.jsonl",
                "databricks_audit": "out/seclog/databricks_audit.jsonl",
                "okta": "out/seclog/okta_system_log.jsonl",
            }
        )
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
    .to(seclog.JsonlSink.payloads("out/seclog/okta_system_log.jsonl"))
    .start(max_events=10_000)
)
```

## Current Scope

The Python package currently supports in-memory generation, persistent stream
iteration, and local JSONL sinks. Managed file output, Databricks volume
uploads, and Zerobus writes remain CLI capabilities. The Okta generator is
schema-faithful for the selected auth, session, and app-access events it emits,
but it is not a full implementation of Okta's event-type catalog.
