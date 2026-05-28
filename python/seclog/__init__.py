"""Python bindings for seclog.

The public API is intentionally small:

    import seclog

    events = seclog.generate(max_events=1000)
    okta_payloads = seclog.payloads(sources=["okta"], max_events=100)
    identities = seclog.identities(seclog.Population(size=50))
    count = seclog.write_payloads_jsonl(
        "out/okta.jsonl",
        population=seclog.Population(size=250),
        sources=["okta"],
        max_events=10_000,
    )

Generated events are dictionaries with the normalized seclog envelope and the
source-native payload. Use ``payloads`` when loading raw CloudTrail,
Databricks audit, or Okta records into a downstream system. Write APIs require
an explicit generation input such as ``population`` or ``config_path``.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, field
import json
from pathlib import Path
import time
from typing import Any, Iterator, Mapping, MutableMapping, Optional, Sequence, Union

try:
    from . import _native
except ImportError as exc:  # pragma: no cover - exercised before extension build
    _native = None  # type: ignore[assignment]
    _native_import_error = exc
else:
    _native_import_error = None


DEFAULT_SOURCES = ("cloudtrail", "databricks_audit", "okta")
DEFAULT_TIMEZONES = (
    ("America/Los_Angeles", 0.55),
    ("Europe/London", 0.25),
    ("Asia/Singapore", 0.20),
)
JsonlDestination = Union[str, Path, Mapping[str, Union[str, Path]]]


@dataclass(frozen=True)
class TimezoneWeight:
    """Weighted home timezone for generated actors."""

    name: str
    weight: float

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "weight": self.weight}


@dataclass(frozen=True)
class ErrorRate:
    """Range used to assign actor-level failure rates."""

    min: float
    max: float
    distribution: str = "uniform"

    def to_dict(self) -> dict[str, Any]:
        return {"min": self.min, "max": self.max, "distribution": self.distribution}


@dataclass(frozen=True)
class Role:
    """Human actor role distribution entry."""

    name: str
    weight: float
    events_per_hour: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "weight": self.weight,
            "events_per_hour": self.events_per_hour,
        }


@dataclass(frozen=True)
class ServiceProfile:
    """Service actor distribution entry."""

    name: str
    weight: float
    events_per_hour: float
    pattern: str = "constant"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "weight": self.weight,
            "events_per_hour": self.events_per_hour,
            "pattern": self.pattern,
        }


@dataclass(frozen=True)
class ExplicitActor:
    """Optional fixed actor definition.

    Names, emails, and platform identifiers may be omitted. Seclog synthesizes
    realistic identity fields from the actor's timezone and location context.
    """

    id: str
    kind: str = "human"
    role: Optional[str] = None
    service_profile: Optional[str] = None
    events_per_hour: Optional[float] = None
    error_rate: Optional[float] = None
    account_id: Optional[str] = None
    timezone: Optional[str] = None
    active_start_hour: Optional[int] = None
    active_hours: Optional[int] = None
    weekend_active: Optional[bool] = None
    user_agents: Optional[Sequence[str]] = None
    source_ips: Optional[Sequence[str]] = None
    tags: Sequence[str] = field(default_factory=tuple)
    event_bias: Mapping[str, float] = field(default_factory=dict)
    user_name: Optional[str] = None
    display_name: Optional[str] = None
    email: Optional[str] = None
    home_location: Optional[str] = None
    normal_countries_regions: Optional[Sequence[str]] = None
    principal_id: Optional[str] = None
    arn: Optional[str] = None
    access_key_id: Optional[str] = None
    identity_type: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "id": self.id,
                "kind": self.kind,
                "role": self.role,
                "service_profile": self.service_profile,
                "events_per_hour": self.events_per_hour,
                "error_rate": self.error_rate,
                "account_id": self.account_id,
                "timezone": self.timezone,
                "active_start_hour": self.active_start_hour,
                "active_hours": self.active_hours,
                "weekend_active": self.weekend_active,
                "user_agents": list(self.user_agents)
                if self.user_agents is not None
                else None,
                "source_ips": list(self.source_ips)
                if self.source_ips is not None
                else None,
                "tags": list(self.tags),
                "event_bias": dict(self.event_bias),
                "user_name": self.user_name,
                "display_name": self.display_name,
                "email": self.email,
                "home_location": self.home_location,
                "normal_countries_regions": list(self.normal_countries_regions)
                if self.normal_countries_regions is not None
                else None,
                "principal_id": self.principal_id,
                "arn": self.arn,
                "access_key_id": self.access_key_id,
                "identity_type": self.identity_type,
            }
        )


@dataclass(frozen=True)
class Population:
    """Configuration for a shared generated identity population."""

    size: int = 250
    seed: int = 42
    service_ratio: float = 0.20
    hot_actor_ratio: float = 0.05
    hot_actor_multiplier: float = 6.0
    account_ids: Sequence[str] = ("123456789012",)
    error_rate: ErrorRate = ErrorRate(0.01, 0.04)
    human_error_rate: ErrorRate = ErrorRate(0.02, 0.06, "normal")
    service_error_rate: ErrorRate = ErrorRate(0.005, 0.02)
    roles: Sequence[Role] = (
        Role("admin", 0.15, 24.0),
        Role("developer", 0.55, 18.0),
        Role("readonly", 0.25, 8.0),
        Role("auditor", 0.05, 6.0),
    )
    service_profiles: Sequence[ServiceProfile] = (
        ServiceProfile("datalake_bot", 0.40, 30.0, "constant"),
        ServiceProfile("ec2_reaper", 0.25, 12.0, "bursty"),
        ServiceProfile("logs_shipper", 0.20, 20.0, "constant"),
        ServiceProfile("metrics_collector", 0.15, 8.0, "diurnal"),
    )
    timezones: Sequence[Union[TimezoneWeight, tuple[str, float]]] = DEFAULT_TIMEZONES
    explicit_actors: Sequence[Union[ExplicitActor, Mapping[str, Any]]] = field(
        default_factory=tuple
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "timezone_distribution": [_timezone_to_dict(tz) for tz in self.timezones],
            "population": _drop_none(
                {
                    "actor_count": self.size,
                    "service_ratio": self.service_ratio,
                    "hot_actor_ratio": self.hot_actor_ratio,
                    "hot_actor_multiplier": self.hot_actor_multiplier,
                    "account_ids": list(self.account_ids),
                    "error_rate": self.error_rate.to_dict(),
                    "human_error_rate": self.human_error_rate.to_dict(),
                    "service_error_rate": self.service_error_rate.to_dict(),
                    "role": [role.to_dict() for role in self.roles],
                    "service_profiles": [
                        profile.to_dict() for profile in self.service_profiles
                    ],
                    "actor": [_actor_to_dict(actor) for actor in self.explicit_actors],
                }
            ),
        }


def default_config(
    *,
    sources: Sequence[str] = DEFAULT_SOURCES,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    seed: Optional[int] = None,
    start_time: str = "2026-01-01T00:00:00Z",
    time_scale: float = 36000.0,
    cloudtrail_regions: Sequence[str] = ("us-east-1", "us-west-2", "ap-southeast-1"),
    cloudtrail_region_distribution: Sequence[float] = (0.55, 0.25, 0.20),
    databricks_account_id: str = "example-account-id",
    databricks_workspace_id: str = "1234567890",
    databricks_baseline_events_per_actor: int = 2,
    okta_org_id: str = "okta-example-org",
    okta_baseline_events_per_actor: int = 2,
    source_overrides: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> dict[str, Any]:
    """Build a complete seclog config using shared-population defaults."""

    population_dict = _population_to_dict(population)
    source_configs = [
        _source_config(
            source,
            cloudtrail_regions=cloudtrail_regions,
            cloudtrail_region_distribution=cloudtrail_region_distribution,
            databricks_account_id=databricks_account_id,
            databricks_workspace_id=databricks_workspace_id,
            databricks_baseline_events_per_actor=databricks_baseline_events_per_actor,
            okta_org_id=okta_org_id,
            okta_baseline_events_per_actor=okta_baseline_events_per_actor,
            overrides=source_overrides,
        )
        for source in sources
    ]

    return {
        "seed": seed if seed is not None else population_dict.get("seed"),
        "traffic": {"start_time": start_time, "time_scale": time_scale},
        "output": {
            "dir": "./out-seclog-python",
            "files": {"target_size_mb": 50, "max_age_seconds": 10},
            "format": {"type": "jsonl", "compression": None},
        },
        "source": {
            "type": "multi",
            "population_config": population_dict,
            "sources": source_configs,
        },
    }


class EventStream:
    """Persistent event stream backed by one Rust generator instance."""

    def __init__(
        self,
        *,
        sources: Sequence[str] = DEFAULT_SOURCES,
        population: Optional[Union[Population, Mapping[str, Any]]] = None,
        config: Optional[Mapping[str, Any]] = None,
        config_path: Optional[Union[str, Path]] = None,
        config_toml: Optional[str] = None,
        **config_kwargs: Any,
    ) -> None:
        kind, value = _config_input(
            config=config,
            config_path=config_path,
            config_toml=config_toml,
            sources=sources,
            population=population,
            config_kwargs=config_kwargs,
        )
        native = _native_module().EventStream
        self._native = native.from_toml(value) if kind == "toml" else native.from_json(value)

    def __iter__(self) -> "EventStream":
        return self

    def __next__(self) -> dict[str, Any]:
        event_json = self._native.next_event_json()
        if event_json is None:
            raise StopIteration
        return json.loads(event_json)

    def batches(self, batch_size: int = 1000) -> Iterator[list[dict[str, Any]]]:
        """Yield batches from the same persistent generator."""

        if batch_size <= 0:
            raise ValueError("batch_size must be greater than zero")
        while True:
            batch = self._native.next_batch_json(batch_size)
            if not batch:
                return
            yield [json.loads(event_json) for event_json in batch]

    def sink_jsonl(
        self,
        destinations: JsonlDestination,
        *,
        max_events: Optional[int] = None,
        payload_only: bool = True,
        flush_every: int = 1000,
        events_per_second: Optional[float] = None,
    ) -> int:
        """Write this stream to one JSONL destination or per-source destinations."""

        return _sink_stream_jsonl(
            self,
            destinations,
            max_events=max_events,
            payload_only=payload_only,
            flush_every=flush_every,
            events_per_second=events_per_second,
        )


def stream(
    *,
    sources: Sequence[str] = DEFAULT_SOURCES,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    config: Optional[Mapping[str, Any]] = None,
    config_path: Optional[Union[str, Path]] = None,
    config_toml: Optional[str] = None,
    **config_kwargs: Any,
) -> EventStream:
    """Create a persistent event stream."""

    return EventStream(
        sources=sources,
        population=population,
        config=config,
        config_path=config_path,
        config_toml=config_toml,
        **config_kwargs,
    )


def generate(
    *,
    max_events: int = 100,
    sources: Sequence[str] = DEFAULT_SOURCES,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    config: Optional[Mapping[str, Any]] = None,
    config_path: Optional[Union[str, Path]] = None,
    config_toml: Optional[str] = None,
    **config_kwargs: Any,
) -> list[dict[str, Any]]:
    """Generate normalized seclog events as dictionaries."""

    return list(
        iter_events(
            max_events=max_events,
            sources=sources,
            population=population,
            config=config,
            config_path=config_path,
            config_toml=config_toml,
            **config_kwargs,
        )
    )


def iter_events(
    *,
    max_events: int = 100,
    sources: Sequence[str] = DEFAULT_SOURCES,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    config: Optional[Mapping[str, Any]] = None,
    config_path: Optional[Union[str, Path]] = None,
    config_toml: Optional[str] = None,
    **config_kwargs: Any,
) -> Iterator[dict[str, Any]]:
    """Iterate generated normalized events."""

    event_jsons = _generate_event_jsons(
        max_events=max_events,
        config=config,
        config_path=config_path,
        config_toml=config_toml,
        sources=sources,
        population=population,
        config_kwargs=config_kwargs,
    )
    for event_json in event_jsons:
        yield json.loads(event_json)


def payloads(
    *,
    max_events: int = 100,
    sources: Sequence[str] = DEFAULT_SOURCES,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    config: Optional[Mapping[str, Any]] = None,
    config_path: Optional[Union[str, Path]] = None,
    config_toml: Optional[str] = None,
    **config_kwargs: Any,
) -> list[dict[str, Any]]:
    """Generate source-native payload dictionaries only."""

    return [
        event["payload"]
        for event in iter_events(
            max_events=max_events,
            sources=sources,
            population=population,
            config=config,
            config_path=config_path,
            config_toml=config_toml,
            **config_kwargs,
        )
    ]


def identities(
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    *,
    population_path: Optional[Union[str, Path]] = None,
    population_toml: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Generate the shared identity registry implied by a population config."""

    population_jsons = _generate_identity_jsons(
        population=population,
        population_path=population_path,
        population_toml=population_toml,
    )
    return [json.loads(identity_json) for identity_json in population_jsons]


def load_config(path: Union[str, Path]) -> dict[str, Any]:
    """Load a seclog TOML generator config as a JSON-compatible dictionary."""

    return json.loads(_native_module().config_toml_to_json(_read_text(path)))


def load_population(path: Union[str, Path]) -> dict[str, Any]:
    """Load a seclog TOML population config as a JSON-compatible dictionary."""

    return json.loads(_native_module().population_toml_to_json(_read_text(path)))


def sink_jsonl(
    destinations: JsonlDestination,
    *,
    max_events: Optional[int],
    payload_only: bool = True,
    flush_every: int = 1000,
    events_per_second: Optional[float] = None,
    sources: Optional[Sequence[str]] = None,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    config: Optional[Mapping[str, Any]] = None,
    config_path: Optional[Union[str, Path]] = None,
    config_toml: Optional[str] = None,
    **config_kwargs: Any,
) -> int:
    """Stream events to one JSONL file or to per-source JSONL files.

    A write must name its generation input. Pass one of ``config``,
    ``config_path``, ``config_toml``, or ``population``.
    """

    _require_explicit_write_input(
        config=config,
        config_path=config_path,
        config_toml=config_toml,
        population=population,
    )
    event_stream = stream(
        sources=sources or DEFAULT_SOURCES,
        population=population,
        config=config,
        config_path=config_path,
        config_toml=config_toml,
        **config_kwargs,
    )
    return event_stream.sink_jsonl(
        destinations,
        max_events=max_events,
        payload_only=payload_only,
        flush_every=flush_every,
        events_per_second=events_per_second,
    )


def _generate_identity_jsons(
    *,
    population: Optional[Union[Population, Mapping[str, Any]]],
    population_path: Optional[Union[str, Path]],
    population_toml: Optional[str],
) -> list[str]:
    configured = sum(
        value is not None for value in (population, population_path, population_toml)
    )
    if configured > 1:
        raise ValueError("set only one of population, population_path, or population_toml")
    if population_path is not None:
        return _native_module().generate_identities_toml(_read_text(population_path))
    if population_toml is not None:
        return _native_module().generate_identities_toml(population_toml)
    population_dict = _population_to_dict(population)
    return [
        identity_json
        for identity_json in _native_module().generate_identities_json(json.dumps(population_dict))
    ]


def write_jsonl(
    path: Union[str, Path],
    *,
    max_events: Optional[int],
    payload_only: bool = False,
    sources: Optional[Sequence[str]] = None,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    config: Optional[Mapping[str, Any]] = None,
    config_path: Optional[Union[str, Path]] = None,
    config_toml: Optional[str] = None,
    flush_every: int = 1000,
    events_per_second: Optional[float] = None,
    **config_kwargs: Any,
) -> int:
    """Write generated events or source-native payloads to a JSONL file.

    Prefer ``write_events_jsonl`` or ``write_payloads_jsonl`` at call sites
    where the row shape should be obvious from the function name.
    """

    return sink_jsonl(
        path,
        max_events=max_events,
        payload_only=payload_only,
        flush_every=flush_every,
        events_per_second=events_per_second,
        sources=sources,
        population=population,
        config=config,
        config_path=config_path,
        config_toml=config_toml,
        **config_kwargs,
    )


def write_events_jsonl(
    path: Union[str, Path],
    *,
    max_events: Optional[int],
    sources: Optional[Sequence[str]] = None,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    config: Optional[Mapping[str, Any]] = None,
    config_path: Optional[Union[str, Path]] = None,
    config_toml: Optional[str] = None,
    flush_every: int = 1000,
    events_per_second: Optional[float] = None,
    **config_kwargs: Any,
) -> int:
    """Write normalized seclog events with ``envelope`` and ``payload`` fields."""

    return sink_jsonl(
        path,
        max_events=max_events,
        payload_only=False,
        flush_every=flush_every,
        events_per_second=events_per_second,
        sources=sources,
        population=population,
        config=config,
        config_path=config_path,
        config_toml=config_toml,
        **config_kwargs,
    )


def write_payloads_jsonl(
    path: Union[str, Path],
    *,
    max_events: Optional[int],
    sources: Optional[Sequence[str]] = None,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    config: Optional[Mapping[str, Any]] = None,
    config_path: Optional[Union[str, Path]] = None,
    config_toml: Optional[str] = None,
    flush_every: int = 1000,
    events_per_second: Optional[float] = None,
    **config_kwargs: Any,
) -> int:
    """Write source-native CloudTrail, Databricks audit, or Okta JSON payloads."""

    return sink_jsonl(
        path,
        max_events=max_events,
        payload_only=True,
        flush_every=flush_every,
        events_per_second=events_per_second,
        sources=sources,
        population=population,
        config=config,
        config_path=config_path,
        config_toml=config_toml,
        **config_kwargs,
    )


def generate_from_config(
    config: Mapping[str, Any],
    *,
    max_events: int = 100,
) -> list[dict[str, Any]]:
    """Generate events from an explicit seclog config dictionary."""

    return generate(config=config, max_events=max_events)


def _generate_event_jsons(
    *,
    max_events: int,
    config: Optional[Mapping[str, Any]],
    config_path: Optional[Union[str, Path]],
    config_toml: Optional[str],
    sources: Sequence[str],
    population: Optional[Union[Population, Mapping[str, Any]]],
    config_kwargs: Mapping[str, Any],
) -> list[str]:
    kind, value = _config_input(
        config=config,
        config_path=config_path,
        config_toml=config_toml,
        sources=sources,
        population=population,
        config_kwargs=config_kwargs,
    )
    if kind == "toml":
        return _native_module().generate_events_toml(value, max_events)
    return _native_module().generate_events_json(value, max_events)


def _require_explicit_write_input(
    *,
    config: Optional[Mapping[str, Any]],
    config_path: Optional[Union[str, Path]],
    config_toml: Optional[str],
    population: Optional[Union[Population, Mapping[str, Any]]],
) -> None:
    if any(value is not None for value in (config, config_path, config_toml, population)):
        return
    raise ValueError(
        "write APIs require an explicit generation input; pass config, "
        "config_path, config_toml, or population"
    )


def _config_input(
    *,
    config: Optional[Mapping[str, Any]],
    config_path: Optional[Union[str, Path]],
    config_toml: Optional[str],
    sources: Sequence[str],
    population: Optional[Union[Population, Mapping[str, Any]]],
    config_kwargs: Mapping[str, Any],
) -> tuple[str, str]:
    configured = sum(value is not None for value in (config, config_path, config_toml))
    if configured > 1:
        raise ValueError("set only one of config, config_path, or config_toml")

    has_code_overrides = (
        tuple(sources) != tuple(DEFAULT_SOURCES)
        or population is not None
        or bool(config_kwargs)
    )
    if config is not None:
        if has_code_overrides:
            raise ValueError("config cannot be combined with source or population arguments")
        return "json", json.dumps(dict(config))
    if config_path is not None:
        if has_code_overrides:
            raise ValueError("config_path cannot be combined with source or population arguments")
        return "toml", _read_text(config_path)
    if config_toml is not None:
        if has_code_overrides:
            raise ValueError("config_toml cannot be combined with source or population arguments")
        return "toml", config_toml

    return "json", json.dumps(
        default_config(sources=sources, population=population, **config_kwargs)
    )


def _sink_stream_jsonl(
    event_stream: EventStream,
    destinations: JsonlDestination,
    *,
    max_events: Optional[int],
    payload_only: bool,
    flush_every: int,
    events_per_second: Optional[float],
) -> int:
    if max_events is not None and max_events < 0:
        raise ValueError("max_events must be non-negative or None")
    if flush_every < 0:
        raise ValueError("flush_every must be non-negative")
    if events_per_second is not None and events_per_second <= 0:
        raise ValueError("events_per_second must be greater than zero")

    count = 0
    interval = 1.0 / events_per_second if events_per_second else None
    next_deadline = time.monotonic()

    with ExitStack() as stack:
        default_handle, route_handles = _open_jsonl_destinations(destinations, stack)
        while max_events is None or count < max_events:
            try:
                event = next(event_stream)
            except StopIteration:
                break

            source = event["envelope"]["source"]
            handle = default_handle or route_handles.get(source)
            if handle is None:
                raise ValueError(f"no JSONL destination configured for source {source}")

            row = event["payload"] if payload_only else event
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")
            count += 1

            if flush_every and count % flush_every == 0:
                _flush_handles(default_handle, route_handles)

            if interval is not None:
                next_deadline += interval
                sleep_seconds = next_deadline - time.monotonic()
                if sleep_seconds > 0:
                    time.sleep(sleep_seconds)

        _flush_handles(default_handle, route_handles)

    return count


def _open_jsonl_destinations(
    destinations: JsonlDestination,
    stack: ExitStack,
) -> tuple[Optional[Any], dict[str, Any]]:
    if isinstance(destinations, Mapping):
        route_handles = {}
        for source, path in destinations.items():
            key = _normalize_source(str(source))
            route_handles[key] = _open_jsonl_path(path, stack)
        return None, route_handles

    return _open_jsonl_path(destinations, stack), {}


def _open_jsonl_path(path: Union[str, Path], stack: ExitStack) -> Any:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    return stack.enter_context(output_path.open("w", encoding="utf-8"))


def _flush_handles(default_handle: Optional[Any], route_handles: Mapping[str, Any]) -> None:
    if default_handle is not None:
        default_handle.flush()
    for handle in route_handles.values():
        handle.flush()


def _read_text(path: Union[str, Path]) -> str:
    return Path(path).read_text(encoding="utf-8")


def _source_config(
    source: str,
    *,
    cloudtrail_regions: Sequence[str],
    cloudtrail_region_distribution: Sequence[float],
    databricks_account_id: str,
    databricks_workspace_id: str,
    databricks_baseline_events_per_actor: int,
    okta_org_id: str,
    okta_baseline_events_per_actor: int,
    overrides: Optional[Mapping[str, Mapping[str, Any]]],
) -> dict[str, Any]:
    normalized = _normalize_source(source)
    if normalized == "cloudtrail":
        config = {
            "type": "cloudtrail",
            "curated": True,
            "regions": list(cloudtrail_regions),
            "region_distribution": list(cloudtrail_region_distribution),
        }
    elif normalized == "databricks_audit":
        config = {
            "type": "databricks_audit",
            "account_id": databricks_account_id,
            "workspace_id": databricks_workspace_id,
            "baseline_events_per_actor": databricks_baseline_events_per_actor,
        }
    elif normalized == "okta_system_log":
        config = {
            "type": "okta",
            "org_id": okta_org_id,
            "baseline_events_per_actor": okta_baseline_events_per_actor,
        }
    else:  # pragma: no cover - _normalize_source raises first
        raise ValueError(f"unsupported seclog source: {source}")

    if overrides:
        override = overrides.get(normalized) or overrides.get(source)
        if override:
            _deep_merge(config, override)
    return config


def _normalize_source(source: str) -> str:
    normalized = source.lower().replace("-", "_")
    aliases = {
        "cloud_trail": "cloudtrail",
        "cloudtrail": "cloudtrail",
        "databricks": "databricks_audit",
        "databricks_audit": "databricks_audit",
        "okta": "okta_system_log",
        "okta_system_log": "okta_system_log",
    }
    try:
        return aliases[normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported seclog source: {source}") from exc


def _population_to_dict(
    population: Optional[Union[Population, Mapping[str, Any]]],
) -> dict[str, Any]:
    if population is None:
        return Population().to_dict()
    if isinstance(population, Population):
        return population.to_dict()
    return dict(population)


def _timezone_to_dict(value: Union[TimezoneWeight, tuple[str, float]]) -> dict[str, Any]:
    if isinstance(value, TimezoneWeight):
        return value.to_dict()
    name, weight = value
    return {"name": name, "weight": weight}


def _actor_to_dict(actor: Union[ExplicitActor, Mapping[str, Any]]) -> dict[str, Any]:
    if isinstance(actor, ExplicitActor):
        return actor.to_dict()
    return dict(actor)


def _drop_none(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None}


def _deep_merge(target: MutableMapping[str, Any], patch: Mapping[str, Any]) -> None:
    for key, value in patch.items():
        if (
            isinstance(value, Mapping)
            and isinstance(target.get(key), MutableMapping)
        ):
            _deep_merge(target[key], value)  # type: ignore[index]
        else:
            target[key] = value


def _native_module() -> Any:
    if _native is None:
        raise RuntimeError(
            "seclog native extension is not built; install with `pip install -e .` "
            "or run `maturin develop` from the repository root"
        ) from _native_import_error
    return _native


__all__ = [
    "DEFAULT_SOURCES",
    "DEFAULT_TIMEZONES",
    "ErrorRate",
    "EventStream",
    "ExplicitActor",
    "Population",
    "Role",
    "ServiceProfile",
    "TimezoneWeight",
    "default_config",
    "generate",
    "generate_from_config",
    "identities",
    "iter_events",
    "load_config",
    "load_population",
    "payloads",
    "sink_jsonl",
    "stream",
    "write_events_jsonl",
    "write_jsonl",
    "write_payloads_jsonl",
]
