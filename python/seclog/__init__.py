"""Python API for seclog.

The public API is intentionally small:

    import seclog

    population = seclog.Population(size=250, seed=42)
    result = (
        seclog.stream(sources=["okta"], population=population)
        .route(okta=seclog.jsonl("out/okta.jsonl"))
        .to_jsonl("out/events.jsonl", record="event")
        .start(max_events=10_000, progress=True)
    )

    events = seclog.generate(max_events=1000)
    okta_payloads = seclog.payloads(sources=["okta"], max_events=100)
    identities = seclog.identities(population)

Generated streams write to explicit sinks. In-memory generation returns
dictionaries with the normalized seclog envelope and the source-native payload.
Write APIs require an explicit generation input such as ``population`` or
``config_path``.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import sys
import time
from typing import (
    Any,
    Callable,
    Iterator,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Union,
)
import uuid

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
Sources = Optional[tuple[str, ...]]


@dataclass(frozen=True)
class JsonlSink:
    """JSONL sink for source-native payloads or normalized seclog events."""

    destinations: JsonlDestination
    record: str = "payload"
    flush_every: int = 1000
    sources: Sources = None

    @classmethod
    def payloads(
        cls,
        destinations: JsonlDestination,
        *,
        flush_every: int = 1000,
    ) -> "JsonlSink":
        """Write source-native payload rows."""

        return cls(destinations=destinations, record="payload", flush_every=flush_every)

    @classmethod
    def events(
        cls,
        destinations: JsonlDestination,
        *,
        flush_every: int = 1000,
    ) -> "JsonlSink":
        """Write normalized rows with envelope and payload."""

        return cls(destinations=destinations, record="event", flush_every=flush_every)

    def __post_init__(self) -> None:
        _validate_jsonl_record(self.record)
        if self.flush_every < 0:
            raise ValueError("flush_every must be non-negative")
        _validate_sources(self.sources)


@dataclass(frozen=True)
class DatabricksVolumeSink:
    """Unity Catalog volume sink using the Databricks SDK Files API."""

    volume_path: str
    workspace_client: Any
    record: str = "payload"
    flush_every: int = 1000
    sources: Sources = None
    overwrite: bool = False
    file_prefix: str = "part"

    def __post_init__(self) -> None:
        _validate_jsonl_record(self.record)
        _validate_sources(self.sources)
        if self.flush_every < 0:
            raise ValueError("flush_every must be non-negative")
        if not self.volume_path.strip():
            raise ValueError("volume_path must be non-empty")
        if not self.file_prefix.strip():
            raise ValueError("file_prefix must be non-empty")


@dataclass(frozen=True)
class ZerobusSink:
    """Databricks Zerobus sink using the Zerobus Python SDK JSON path."""

    table: str
    workspace_client: Any
    sources: Sources = None
    region: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    client_id_env: str = "DATABRICKS_CLIENT_ID"
    client_secret_env: str = "DATABRICKS_CLIENT_SECRET"
    flush_every: int = 1000

    def __post_init__(self) -> None:
        _validate_sources(self.sources)
        if not self.table.strip():
            raise ValueError("table must be non-empty")
        if self.flush_every < 0:
            raise ValueError("flush_every must be non-negative")


Sink = Union[JsonlSink, DatabricksVolumeSink, ZerobusSink]
RouteValue = Union[Sink, Sequence[Sink]]


def jsonl(
    path: Union[str, Path],
    *,
    record: str = "payload",
    flush_every: int = 1000,
) -> JsonlSink:
    """Create a JSONL sink for use in ``stream(...).route(...)``."""

    return JsonlSink(destinations=path, record=record, flush_every=flush_every)


def volume(
    volume_path: str,
    *,
    workspace_client: Any,
    record: str = "payload",
    flush_every: int = 1000,
    overwrite: bool = False,
    file_prefix: str = "part",
) -> DatabricksVolumeSink:
    """Create a Unity Catalog volume sink for use in ``stream(...).route(...)``."""

    return DatabricksVolumeSink(
        volume_path=volume_path,
        workspace_client=workspace_client,
        record=record,
        flush_every=flush_every,
        overwrite=overwrite,
        file_prefix=file_prefix,
    )


def zerobus(
    table: str,
    *,
    workspace_client: Any,
    region: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    client_id_env: str = "DATABRICKS_CLIENT_ID",
    client_secret_env: str = "DATABRICKS_CLIENT_SECRET",
    flush_every: int = 1000,
) -> ZerobusSink:
    """Create a Zerobus sink for use in ``stream(...).route(...)``."""

    return ZerobusSink(
        table=table,
        workspace_client=workspace_client,
        region=region,
        client_id=client_id,
        client_secret=client_secret,
        client_id_env=client_id_env,
        client_secret_env=client_secret_env,
        flush_every=flush_every,
    )


@dataclass(frozen=True)
class StreamResult:
    """Result returned after a stream finishes writing to sinks."""

    events: int
    elapsed_seconds: float
    events_per_second: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": self.events,
            "elapsed_seconds": self.elapsed_seconds,
            "events_per_second": self.events_per_second,
        }


@dataclass(frozen=True)
class ProgressCounter:
    """Event count and rates for one source or sink."""

    name: str
    events: int
    events_per_second: float
    interval_events: int
    interval_events_per_second: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "events": self.events,
            "events_per_second": self.events_per_second,
            "interval_events": self.interval_events,
            "interval_events_per_second": self.interval_events_per_second,
        }


@dataclass(frozen=True)
class ProgressSnapshot:
    """Progress snapshot emitted while a stream sink is running."""

    events: int
    elapsed_seconds: float
    events_per_second: float
    interval_events: int
    interval_seconds: float
    interval_events_per_second: float
    sources: Mapping[str, ProgressCounter]
    sinks: Mapping[str, ProgressCounter]
    simulated_high_water: Optional[datetime] = None
    simulated_elapsed_seconds: Optional[float] = None
    finished: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": self.events,
            "elapsed_seconds": self.elapsed_seconds,
            "events_per_second": self.events_per_second,
            "interval_events": self.interval_events,
            "interval_seconds": self.interval_seconds,
            "interval_events_per_second": self.interval_events_per_second,
            "sources": {
                name: counter.to_dict() for name, counter in self.sources.items()
            },
            "sinks": {name: counter.to_dict() for name, counter in self.sinks.items()},
            "simulated_high_water": (
                _format_datetime_utc(self.simulated_high_water)
                if self.simulated_high_water is not None
                else None
            ),
            "simulated_elapsed_seconds": self.simulated_elapsed_seconds,
            "finished": self.finished,
        }

    def format(self) -> str:
        return _format_progress_log(self)


ProgressReporter = Union[bool, Callable[[ProgressSnapshot], None]]


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
    identity_registry_path: Optional[Union[str, Path]] = None,
    population_config_path: Optional[Union[str, Path]] = None,
    seed: Optional[int] = None,
    start_time: str = "2026-01-01T00:00:00Z",
    time_scale: float = 36000.0,
    cloudtrail_regions: Sequence[str] = ("us-east-1", "us-west-2", "ap-southeast-1"),
    cloudtrail_region_distribution: Sequence[float] = (0.55, 0.25, 0.20),
    databricks_account_id: str = "example-account-id",
    databricks_workspace_id: Optional[str] = None,
    workspace_client: Any = None,
    databricks_baseline_events_per_actor: Optional[int] = None,
    okta_org_id: str = "okta-example-org",
    okta_baseline_events_per_actor: Optional[int] = None,
    source_overrides: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> dict[str, Any]:
    """Build a complete seclog config using shared-population defaults."""

    if identity_registry_path is not None and population_config_path is not None:
        raise ValueError("set only one of identity_registry_path or population_config_path")
    if databricks_workspace_id is None and workspace_client is not None:
        databricks_workspace_id = _workspace_id(workspace_client)
    databricks_workspace_id = databricks_workspace_id or "1234567890"
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
        "source": _multi_source_config(
            source_configs,
            population_config=population_dict,
            identity_registry_path=identity_registry_path,
            population_config_path=population_config_path,
        ),
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
        progress: Optional[ProgressReporter] = None,
        progress_interval_seconds: float = 5.0,
    ) -> int:
        """Write this stream to one JSONL destination or per-source destinations."""

        result = self.to_jsonl(
            destinations,
            record="payload" if payload_only else "event",
            flush_every=flush_every,
        ).start(
            max_events=max_events,
            events_per_second=events_per_second,
            progress=progress,
            progress_interval_seconds=progress_interval_seconds,
        )
        return result.events

    def to(self, *sinks: Sink) -> "StreamPipeline":
        """Attach one or more sinks to this stream."""

        return StreamPipeline(self, sinks)

    def route(
        self,
        routes: Optional[Mapping[str, RouteValue]] = None,
        **source_routes: RouteValue,
    ) -> "StreamPipeline":
        """Attach sinks by source in one route map."""

        return StreamPipeline(self, _route_sinks(routes, source_routes))

    def source(self, *sources: str) -> "SourceRoute":
        """Select source events before attaching one or more sinks."""

        return SourceRoute(self, (), _normalize_sources(sources))

    def to_jsonl(
        self,
        destinations: JsonlDestination,
        *,
        record: str = "payload",
        flush_every: int = 1000,
    ) -> "StreamPipeline":
        """Attach a JSONL sink to this stream."""

        return self.to(
            JsonlSink(destinations=destinations, record=record, flush_every=flush_every)
        )

    def to_jsonl_by_source(
        self,
        destinations: Optional[Mapping[str, Union[str, Path]]] = None,
        *,
        record: str = "payload",
        flush_every: int = 1000,
        **source_destinations: Union[str, Path],
    ) -> "StreamPipeline":
        """Attach a JSONL sink with explicit source-to-path routes."""

        return self.to_jsonl(
            _source_route_destinations(destinations, source_destinations),
            record=record,
            flush_every=flush_every,
        )

    def to_volume(
        self,
        volume_path: str,
        *,
        workspace_client: Any,
        record: str = "payload",
        flush_every: int = 1000,
        overwrite: bool = False,
        file_prefix: str = "part",
    ) -> "StreamPipeline":
        """Attach a Databricks volume sink for all stream sources."""

        return self.to(
            DatabricksVolumeSink(
                volume_path=volume_path,
                workspace_client=workspace_client,
                record=record,
                flush_every=flush_every,
                overwrite=overwrite,
                file_prefix=file_prefix,
            )
        )

    def to_zerobus(
        self,
        table: str,
        *,
        workspace_client: Any,
        region: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        client_id_env: str = "DATABRICKS_CLIENT_ID",
        client_secret_env: str = "DATABRICKS_CLIENT_SECRET",
        flush_every: int = 1000,
    ) -> "StreamPipeline":
        """Attach a Databricks Zerobus sink for all stream sources."""

        return self.to(
            ZerobusSink(
                table=table,
                workspace_client=workspace_client,
                region=region,
                client_id=client_id,
                client_secret=client_secret,
                client_id_env=client_id_env,
                client_secret_env=client_secret_env,
                flush_every=flush_every,
            )
        )


class StreamPipeline:
    """Configured stream plus its output sinks."""

    def __init__(self, event_stream: EventStream, sinks: Sequence[Sink]) -> None:
        if not sinks:
            raise ValueError("configure at least one sink before starting a stream")
        self._event_stream = event_stream
        self._sinks = tuple(sinks)

    def to(self, *sinks: Sink) -> "StreamPipeline":
        """Attach additional sinks to this stream."""

        if not sinks:
            raise ValueError("configure at least one sink")
        return StreamPipeline(self._event_stream, (*self._sinks, *sinks))

    def route(
        self,
        routes: Optional[Mapping[str, RouteValue]] = None,
        **source_routes: RouteValue,
    ) -> "StreamPipeline":
        """Attach additional sinks by source in one route map."""

        return self.to(*_route_sinks(routes, source_routes))

    def source(self, *sources: str) -> "SourceRoute":
        """Select source events before attaching additional sinks."""

        return SourceRoute(self._event_stream, self._sinks, _normalize_sources(sources))

    def to_jsonl(
        self,
        destinations: JsonlDestination,
        *,
        record: str = "payload",
        flush_every: int = 1000,
    ) -> "StreamPipeline":
        """Attach an additional JSONL sink to this stream."""

        return self.to(
            JsonlSink(destinations=destinations, record=record, flush_every=flush_every)
        )

    def to_jsonl_by_source(
        self,
        destinations: Optional[Mapping[str, Union[str, Path]]] = None,
        *,
        record: str = "payload",
        flush_every: int = 1000,
        **source_destinations: Union[str, Path],
    ) -> "StreamPipeline":
        """Attach an additional JSONL sink with explicit source-to-path routes."""

        return self.to_jsonl(
            _source_route_destinations(destinations, source_destinations),
            record=record,
            flush_every=flush_every,
        )

    def to_volume(
        self,
        volume_path: str,
        *,
        workspace_client: Any,
        record: str = "payload",
        flush_every: int = 1000,
        overwrite: bool = False,
        file_prefix: str = "part",
    ) -> "StreamPipeline":
        """Attach an additional Databricks volume sink for all sources."""

        return self.to(
            DatabricksVolumeSink(
                volume_path=volume_path,
                workspace_client=workspace_client,
                record=record,
                flush_every=flush_every,
                overwrite=overwrite,
                file_prefix=file_prefix,
            )
        )

    def to_zerobus(
        self,
        table: str,
        *,
        workspace_client: Any,
        region: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        client_id_env: str = "DATABRICKS_CLIENT_ID",
        client_secret_env: str = "DATABRICKS_CLIENT_SECRET",
        flush_every: int = 1000,
    ) -> "StreamPipeline":
        """Attach an additional Databricks Zerobus sink for all sources."""

        return self.to(
            ZerobusSink(
                table=table,
                workspace_client=workspace_client,
                region=region,
                client_id=client_id,
                client_secret=client_secret,
                client_id_env=client_id_env,
                client_secret_env=client_secret_env,
                flush_every=flush_every,
            )
        )

    def start(
        self,
        *,
        max_events: Optional[int] = None,
        events_per_second: Optional[float] = None,
        until_time: Optional[Union[str, datetime]] = None,
        time_scale: Optional[float] = None,
        progress: Optional[ProgressReporter] = None,
        progress_interval_seconds: float = 5.0,
    ) -> StreamResult:
        """Start generation and write events to the configured sinks.

        This call is blocking. It returns when ``max_events`` is reached, the
        configured sources are exhausted, or an error is raised.
        """

        return _run_stream_to_sinks(
            self._event_stream,
            self._sinks,
            max_events=max_events,
            events_per_second=events_per_second,
            until_time=until_time,
            time_scale=time_scale,
            progress=progress,
            progress_interval_seconds=progress_interval_seconds,
        )


class SourceRoute:
    """Source-scoped sink builder for explicit routing."""

    def __init__(
        self,
        event_stream: EventStream,
        sinks: Sequence[Sink],
        sources: tuple[str, ...],
    ) -> None:
        self._event_stream = event_stream
        self._sinks = tuple(sinks)
        self._sources = sources

    def source(self, *sources: str) -> "SourceRoute":
        """Select a different source route while keeping configured sinks."""

        return SourceRoute(self._event_stream, self._sinks, _normalize_sources(sources))

    def to(self, *sinks: Sink) -> "SourceRoute":
        """Attach sinks to this source route."""

        if not sinks:
            raise ValueError("configure at least one sink")
        return SourceRoute(self._event_stream, (*self._sinks, *sinks), self._sources)

    def to_jsonl(
        self,
        path: Union[str, Path],
        *,
        record: str = "payload",
        flush_every: int = 1000,
    ) -> "SourceRoute":
        """Route the selected source events to a JSONL file."""

        return self.to(
            JsonlSink(
                destinations=path,
                record=record,
                flush_every=flush_every,
                sources=self._sources,
            )
        )

    def to_volume(
        self,
        volume_path: str,
        *,
        workspace_client: Any,
        record: str = "payload",
        flush_every: int = 1000,
        overwrite: bool = False,
        file_prefix: str = "part",
    ) -> "SourceRoute":
        """Route the selected source events to a Databricks volume."""

        return self.to(
            DatabricksVolumeSink(
                volume_path=volume_path,
                workspace_client=workspace_client,
                record=record,
                flush_every=flush_every,
                sources=self._sources,
                overwrite=overwrite,
                file_prefix=file_prefix,
            )
        )

    def to_zerobus(
        self,
        table: str,
        *,
        workspace_client: Any,
        region: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        client_id_env: str = "DATABRICKS_CLIENT_ID",
        client_secret_env: str = "DATABRICKS_CLIENT_SECRET",
        flush_every: int = 1000,
    ) -> "SourceRoute":
        """Route the selected source events to a Databricks Zerobus table."""

        return self.to(
            ZerobusSink(
                table=table,
                workspace_client=workspace_client,
                sources=self._sources,
                region=region,
                client_id=client_id,
                client_secret=client_secret,
                client_id_env=client_id_env,
                client_secret_env=client_secret_env,
                flush_every=flush_every,
            )
        )

    def start(
        self,
        *,
        max_events: Optional[int] = None,
        events_per_second: Optional[float] = None,
        until_time: Optional[Union[str, datetime]] = None,
        time_scale: Optional[float] = None,
        progress: Optional[ProgressReporter] = None,
        progress_interval_seconds: float = 5.0,
    ) -> StreamResult:
        """Start generation and write events to the configured source routes."""

        return _run_stream_to_sinks(
            self._event_stream,
            self._sinks,
            max_events=max_events,
            events_per_second=events_per_second,
            until_time=until_time,
            time_scale=time_scale,
            progress=progress,
            progress_interval_seconds=progress_interval_seconds,
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
    progress: Optional[ProgressReporter] = None,
    progress_interval_seconds: float = 5.0,
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
        progress=progress,
        progress_interval_seconds=progress_interval_seconds,
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
    progress: Optional[ProgressReporter] = None,
    progress_interval_seconds: float = 5.0,
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
        progress=progress,
        progress_interval_seconds=progress_interval_seconds,
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
    progress: Optional[ProgressReporter] = None,
    progress_interval_seconds: float = 5.0,
    **config_kwargs: Any,
) -> int:
    """Write normalized seclog events with ``envelope`` and ``payload`` fields."""

    return sink_jsonl(
        path,
        max_events=max_events,
        payload_only=False,
        flush_every=flush_every,
        events_per_second=events_per_second,
        progress=progress,
        progress_interval_seconds=progress_interval_seconds,
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
    progress: Optional[ProgressReporter] = None,
    progress_interval_seconds: float = 5.0,
    **config_kwargs: Any,
) -> int:
    """Write source-native CloudTrail, Databricks audit, or Okta JSON payloads."""

    return sink_jsonl(
        path,
        max_events=max_events,
        payload_only=True,
        flush_every=flush_every,
        events_per_second=events_per_second,
        progress=progress,
        progress_interval_seconds=progress_interval_seconds,
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


class _ProgressTracker:
    def __init__(
        self,
        progress: Optional[ProgressReporter],
        progress_interval_seconds: float,
    ) -> None:
        self._reporter = _progress_reporter(progress)
        self._progress_interval_seconds = progress_interval_seconds
        self._started_at = time.monotonic()
        self._last_report_at = self._started_at
        self._events = 0
        self._interval_events = 0
        self._source_events: dict[str, int] = {}
        self._sink_events: dict[str, int] = {}
        self._interval_source_events: dict[str, int] = {}
        self._interval_sink_events: dict[str, int] = {}
        self._simulated_start: Optional[datetime] = None
        self._simulated_high_water: Optional[datetime] = None

    def record_event(self, source: str, event_time: Optional[datetime] = None) -> None:
        if self._reporter is None:
            return

        self._events += 1
        self._interval_events += 1
        _increment_counter(self._source_events, source)
        _increment_counter(self._interval_source_events, source)
        if event_time is not None:
            if self._simulated_start is None:
                self._simulated_start = event_time
            if self._simulated_high_water is None or event_time > self._simulated_high_water:
                self._simulated_high_water = event_time

    def record_sink(self, sink: str) -> None:
        if self._reporter is None:
            return

        _increment_counter(self._sink_events, sink)
        _increment_counter(self._interval_sink_events, sink)

    def maybe_emit(self) -> None:
        if self._reporter is None:
            return
        now = time.monotonic()
        if now - self._last_report_at >= self._progress_interval_seconds:
            self._emit(now, finished=False)

    def record(
        self,
        source: str,
        sink: str,
        event_time: Optional[datetime] = None,
    ) -> None:
        self.record_event(source, event_time)
        self.record_sink(sink)
        self.maybe_emit()

    def finish(self) -> None:
        if self._reporter is None:
            return
        self._emit(time.monotonic(), finished=True)

    def _emit(self, now: float, *, finished: bool) -> None:
        elapsed = max(now - self._started_at, 0.000_001)
        interval_elapsed = max(now - self._last_report_at, 0.000_001)
        snapshot = ProgressSnapshot(
            events=self._events,
            elapsed_seconds=elapsed,
            events_per_second=self._events / elapsed,
            interval_events=self._interval_events,
            interval_seconds=interval_elapsed,
            interval_events_per_second=self._interval_events / interval_elapsed,
            sources=_progress_counters(
                totals=self._source_events,
                intervals=self._interval_source_events,
                elapsed_seconds=elapsed,
                interval_seconds=interval_elapsed,
            ),
            sinks=_progress_counters(
                totals=self._sink_events,
                intervals=self._interval_sink_events,
                elapsed_seconds=elapsed,
                interval_seconds=interval_elapsed,
            ),
            simulated_high_water=self._simulated_high_water,
            simulated_elapsed_seconds=_simulated_elapsed_seconds(
                self._simulated_start,
                self._simulated_high_water,
            ),
            finished=finished,
        )
        self._reporter(snapshot)
        self._last_report_at = now
        self._interval_events = 0
        self._interval_source_events.clear()
        self._interval_sink_events.clear()


def _progress_reporter(
    progress: Optional[ProgressReporter],
) -> Optional[Callable[[ProgressSnapshot], None]]:
    if progress is None or progress is False:
        return None
    if progress is True:
        return _ConsoleProgressRenderer()
    if callable(progress):
        return progress
    raise ValueError("progress must be True, False, None, or a callable")


class _ConsoleProgressRenderer:
    def __init__(self, stream: Any = None) -> None:
        self._stream = stream if stream is not None else sys.stderr
        isatty = getattr(self._stream, "isatty", None)
        self._interactive = bool(isatty()) if callable(isatty) else False
        self._rendered_lines = 0

    def __call__(self, snapshot: ProgressSnapshot) -> None:
        if not self._interactive:
            self._stream.write(_format_progress_log(snapshot) + "\n")
            self._stream.flush()
            return

        text = _format_progress_block(snapshot)
        lines = text.count("\n") + 1
        if self._rendered_lines:
            self._stream.write(f"\x1b[{self._rendered_lines}F")
            self._stream.write("\x1b[J")

        self._stream.write(text + "\n")
        self._stream.flush()
        self._rendered_lines = lines


def _increment_counter(counters: MutableMapping[str, int], key: str) -> None:
    counters[key] = counters.get(key, 0) + 1


def _progress_counters(
    *,
    totals: Mapping[str, int],
    intervals: Mapping[str, int],
    elapsed_seconds: float,
    interval_seconds: float,
) -> dict[str, ProgressCounter]:
    return {
        name: ProgressCounter(
            name=name,
            events=events,
            events_per_second=events / elapsed_seconds,
            interval_events=intervals.get(name, 0),
            interval_events_per_second=intervals.get(name, 0) / interval_seconds,
        )
        for name, events in totals.items()
    }


def _simulated_elapsed_seconds(
    start: Optional[datetime],
    high_water: Optional[datetime],
) -> Optional[float]:
    if start is None or high_water is None:
        return None
    return max((high_water - start).total_seconds(), 0.0)


def _format_progress_counters(counters: Mapping[str, ProgressCounter]) -> str:
    if not counters:
        return "-"
    return ", ".join(
        f"{name}:{counter.events}@{counter.interval_events_per_second:.1f}/s"
        for name, counter in counters.items()
    )


def _format_progress_log(snapshot: ProgressSnapshot) -> str:
    status = "complete" if snapshot.finished else "running"
    simulated = ""
    if snapshot.simulated_high_water is not None:
        simulated = (
            f" | simulated={_format_datetime_utc(snapshot.simulated_high_water)}"
            f" | sim_elapsed={_format_duration(snapshot.simulated_elapsed_seconds or 0.0)}"
        )
    lines = [
        (
            f"seclog progress | {status} | total={_format_count(snapshot.events)} "
            f"| +{_format_count(snapshot.interval_events)} "
            f"| current={_format_rate(snapshot.interval_events_per_second)} "
            f"| avg={_format_rate(snapshot.events_per_second)} "
            f"| elapsed={_format_duration(snapshot.elapsed_seconds)}"
            f"{simulated}"
        ),
        *_format_progress_log_section("sources", snapshot.sources),
        *_format_progress_log_section("sinks", snapshot.sinks),
    ]
    return "\n".join(lines)


def _format_progress_log_section(
    title: str,
    counters: Mapping[str, ProgressCounter],
) -> list[str]:
    lines = [f"  {title}:"]
    if not counters:
        lines.append("    - | total=0 | +0 | current=0.0/s | avg=0.0/s")
        return lines

    for counter in sorted(counters.values(), key=lambda item: item.name):
        lines.append(
            f"    {counter.name} | total={_format_count(counter.events)} "
            f"| +{_format_count(counter.interval_events)} "
            f"| current={_format_rate(counter.interval_events_per_second)} "
            f"| avg={_format_rate(counter.events_per_second)}"
        )
    return lines


def _format_progress_block(snapshot: ProgressSnapshot) -> str:
    status = "complete" if snapshot.finished else "running"
    simulated = ""
    if snapshot.simulated_high_water is not None:
        simulated = (
            f" | sim {_format_datetime_utc(snapshot.simulated_high_water)}"
            f" ({_format_duration(snapshot.simulated_elapsed_seconds or 0.0)})"
        )
    header = (
        f"seclog {status} | {_format_count(snapshot.events)} events | "
        f"{_format_rate(snapshot.events_per_second)} avg | "
        f"{_format_rate(snapshot.interval_events_per_second)} current | "
        f"{_format_duration(snapshot.elapsed_seconds)} elapsed"
        f"{simulated}"
    )
    return "\n".join(
        [
            header,
            _format_progress_table("sources", snapshot.sources),
            _format_progress_table("sinks", snapshot.sinks),
        ]
    )


def _format_progress_table(
    title: str,
    counters: Mapping[str, ProgressCounter],
) -> str:
    lines = [
        title,
        "  name                                      events       avg/s   current/s",
    ]
    if not counters:
        lines.append("  -                                              0         0.0         0.0")
        return "\n".join(lines)

    for counter in sorted(counters.values(), key=lambda item: (-item.events, item.name)):
        name = _shorten_middle(counter.name, 40)
        lines.append(
            f"  {name:<40} "
            f"{_format_count(counter.events):>10} "
            f"{counter.events_per_second:>11.1f} "
            f"{counter.interval_events_per_second:>11.1f}"
        )
    return "\n".join(lines)


def _format_count(value: int) -> str:
    return f"{value:,}"


def _format_rate(value: float) -> str:
    return f"{value:,.1f}/s"


def _format_duration(seconds: float) -> str:
    total = int(seconds)
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _shorten_middle(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    prefix = (width - 3) // 2
    suffix = width - 3 - prefix
    return f"{value[:prefix]}...{value[-suffix:]}"


def _validate_jsonl_record(record: str) -> None:
    if record not in {"payload", "event"}:
        raise ValueError("JSONL sink record must be 'payload' or 'event'")


def _jsonl_record_payload_only(record: str) -> bool:
    _validate_jsonl_record(record)
    return record == "payload"


def _event_record(event: Mapping[str, Any], record: str) -> Any:
    return event["payload"] if _jsonl_record_payload_only(record) else event


def _validate_sources(sources: Sources) -> None:
    if sources is None:
        return
    if not sources:
        raise ValueError("source routes must include at least one source")
    for source in sources:
        _normalize_source(source)


def _normalize_sources(sources: Sequence[str]) -> tuple[str, ...]:
    if not sources:
        raise ValueError("select at least one source")
    normalized: list[str] = []
    for source in sources:
        value = _normalize_source(source)
        if value not in normalized:
            normalized.append(value)
    return tuple(normalized)


def _matches_sources(sources: Sources, source: str) -> bool:
    if sources is None:
        return True
    return _normalize_source(source) in {_normalize_source(item) for item in sources}


def _route_sinks(
    routes: Optional[Mapping[str, RouteValue]],
    source_routes: Mapping[str, RouteValue],
) -> tuple[Sink, ...]:
    merged: dict[str, RouteValue] = {}
    if routes is not None:
        merged.update(routes)
    merged.update(source_routes)
    if not merged:
        raise ValueError("configure at least one source route")

    routed: list[Sink] = []
    for source, value in merged.items():
        sources = (_normalize_source(source),)
        for sink in _route_value_sinks(value):
            routed.append(_sink_with_sources(sink, sources))
    return tuple(routed)


def _route_value_sinks(value: RouteValue) -> tuple[Sink, ...]:
    if _is_sink(value):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        sinks = tuple(value)
        if not sinks:
            raise ValueError("source route must include at least one sink")
        for sink in sinks:
            if not _is_sink(sink):
                raise TypeError(
                    "source route values must be seclog.jsonl(...), "
                    "seclog.volume(...), seclog.zerobus(...), or a list of them"
                )
        return sinks
    raise TypeError(
        "source route values must be seclog.jsonl(...), seclog.volume(...), "
        "seclog.zerobus(...), or a list of them"
    )


def _is_sink(value: object) -> bool:
    return isinstance(value, (JsonlSink, DatabricksVolumeSink, ZerobusSink))


def _sink_with_sources(sink: Sink, sources: tuple[str, ...]) -> Sink:
    return replace(sink, sources=sources)


def _source_route_destinations(
    destinations: Optional[Mapping[str, Union[str, Path]]],
    source_destinations: Mapping[str, Union[str, Path]],
) -> dict[str, Union[str, Path]]:
    routes: dict[str, Union[str, Path]] = {}
    if destinations is not None:
        routes.update(destinations)
    routes.update(source_destinations)
    if not routes:
        raise ValueError("configure at least one source route")
    return routes


def _normalize_volume_path(path: str) -> str:
    value = path.strip()
    if value.startswith("dbfs:/Volumes/"):
        value = value[len("dbfs:"):]
    value = value.rstrip("/")
    parts = value.split("/")
    if len(parts) < 5 or parts[:2] != ["", "Volumes"]:
        raise ValueError(
            "volume_path must start with /Volumes/<catalog>/<schema>/<volume> "
            "or dbfs:/Volumes/..."
        )
    return value


def _safe_volume_segment(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._=-" else "_" for char in value)


def _event_to_zerobus_row(
    event: Mapping[str, Any],
    run_id: str,
    generated_at: datetime,
) -> dict[str, Any]:
    envelope = event["envelope"]
    payload = event["payload"]
    timestamp = str(envelope.get("timestamp", ""))
    parsed_time = _parse_rfc3339(timestamp)
    actor = envelope.get("actor") or {}
    target = envelope.get("target") or {}

    return {
        "time": (
            int(parsed_time.timestamp() * 1_000_000)
            if parsed_time is not None
            else None
        ),
        "event_time": timestamp,
        "event_date": parsed_time.strftime("%Y-%m-%d") if parsed_time else None,
        "event_ts_ms": (
            int(parsed_time.timestamp() * 1_000)
            if parsed_time is not None
            else None
        ),
        "source": envelope.get("source"),
        "event_type": envelope.get("event_type"),
        "actor_id": actor.get("id"),
        "actor_kind": actor.get("kind"),
        "actor_name": actor.get("name"),
        "target_id": target.get("id"),
        "target_kind": target.get("kind"),
        "target_name": target.get("name"),
        "outcome": envelope.get("outcome"),
        "ip": envelope.get("ip"),
        "user_agent": envelope.get("user_agent"),
        "session_id": envelope.get("session_id"),
        "tenant_id": envelope.get("tenant_id"),
        "envelope_json": json.dumps(envelope, separators=(",", ":")),
        "payload_json": json.dumps(payload, separators=(",", ":")),
        "run_id": run_id,
        "generated_at": _format_datetime_utc(generated_at),
    }


def _parse_rfc3339(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_datetime_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _workspace_config_attr(workspace_client: Any, name: str) -> Optional[str]:
    config = getattr(workspace_client, "config", None)
    value = getattr(config, name, None) if config is not None else None
    return str(value) if value else None


def _workspace_host(workspace_client: Any) -> str:
    host = _workspace_config_attr(workspace_client, "host")
    if not host:
        raise ValueError("workspace_client.config.host is required")
    return host.rstrip("/")


def _workspace_id(workspace_client: Any) -> str:
    get_workspace_id = getattr(workspace_client, "get_workspace_id", None)
    if callable(get_workspace_id):
        workspace_id = get_workspace_id()
        if workspace_id:
            return str(workspace_id)
    workspace_id = _workspace_config_attr(workspace_client, "workspace_id")
    if workspace_id:
        return workspace_id
    raise ValueError("workspace_client must provide get_workspace_id() or config.workspace_id")


def _infer_zerobus_endpoint(
    workspace_client: Any,
    region: Optional[str],
) -> str:
    workspace_id = _workspace_id(workspace_client)
    workspace_region = region or _infer_workspace_region(workspace_client, workspace_id)
    suffix = _workspace_cloud_suffix(workspace_client)
    return f"https://{workspace_id}.zerobus.{workspace_region}.{suffix}"


def _infer_workspace_region(workspace_client: Any, workspace_id: str) -> str:
    for attr in ("region", "aws_region", "location"):
        value = _workspace_config_attr(workspace_client, attr)
        if value:
            return value

    region = _workspace_metastore_region(workspace_client)
    if region:
        return region

    workspace_config = _workspace_config_details(workspace_client)
    region = _workspace_config_region(workspace_config)
    if region:
        return region

    account_id = (
        _workspace_config_attr(workspace_client, "account_id")
        or _api_client_attr(workspace_client, "account_id")
        or _workspace_config_account_id(workspace_config)
    )
    if account_id:
        region = _workspace_region_from_account_endpoint(
            workspace_client,
            account_id,
            workspace_id,
        )
        if region:
            return region

        try:
            from databricks.sdk import AccountClient  # type: ignore[import-not-found]

            account_client = AccountClient(account_id=account_id)
            workspace = account_client.workspaces.get(workspace_id=int(workspace_id))
            for attr in ("aws_region", "location", "region"):
                value = getattr(workspace, attr, None)
                if value:
                    return str(value)
        except Exception:
            pass

    raise ValueError(
        "could not infer Databricks workspace region for Zerobus from "
        "WorkspaceClient config, metastore summary, /config, or account workspace "
        "details; pass region="
    )


def _workspace_cloud_suffix(workspace_client: Any) -> str:
    cloud = _workspace_cloud(workspace_client)
    if cloud in ("azure", "azure_public", "azure_us_gov"):
        return "azuredatabricks.net"
    if cloud in ("gcp", "google"):
        return "gcp.databricks.com"
    if cloud == "aws":
        return "cloud.databricks.com"

    host = _workspace_host(workspace_client)
    if host.endswith(".azuredatabricks.net"):
        return "azuredatabricks.net"
    if host.endswith(".gcp.databricks.com"):
        return "gcp.databricks.com"
    return "cloud.databricks.com"


def _workspace_cloud(workspace_client: Any) -> Optional[str]:
    config = getattr(workspace_client, "config", None)
    environment = getattr(config, "environment", None) if config is not None else None
    cloud = getattr(environment, "cloud", None) if environment is not None else None
    value = getattr(cloud, "value", None) if cloud is not None else None
    cloud_value = value or cloud
    if not cloud_value:
        return None
    return str(cloud_value).lower().rsplit(".", 1)[-1]


def _workspace_metastore_region(workspace_client: Any) -> Optional[str]:
    metastores = getattr(workspace_client, "metastores", None)
    summary = getattr(metastores, "summary", None) if metastores is not None else None
    if not callable(summary):
        return None
    try:
        details = summary()
    except Exception:
        return None

    region = _object_field(details, "region")
    if region:
        return region

    global_metastore_id = _object_field(details, "global_metastore_id")
    if global_metastore_id:
        return _region_from_global_metastore_id(global_metastore_id)
    return None


def _object_field(value: Any, name: str) -> Optional[str]:
    if isinstance(value, Mapping):
        field = value.get(name)
        return str(field) if field not in (None, "") else None

    field = getattr(value, name, None)
    if field not in (None, ""):
        return str(field)

    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict):
        try:
            fields = as_dict()
        except Exception:
            return None
        if isinstance(fields, Mapping):
            field = fields.get(name)
            return str(field) if field not in (None, "") else None
    return None


def _region_from_global_metastore_id(value: str) -> Optional[str]:
    parts = value.split(":")
    if len(parts) >= 3 and parts[1]:
        return parts[1]
    return None


def _workspace_config_details(workspace_client: Any) -> dict[str, Any]:
    response = _workspace_api_do(workspace_client, "GET", "/config")
    details = _parse_workspace_config_response(response)
    if details:
        return details
    return {}


def _workspace_region_from_account_endpoint(
    workspace_client: Any,
    account_id: str,
    workspace_id: str,
) -> Optional[str]:
    path = f"/api/2.0/accounts/{account_id}/workspaces/{workspace_id}"
    response = _workspace_api_do(workspace_client, "GET", path)
    details = _parse_workspace_config_response(response)
    return _account_workspace_region(details)


def _workspace_api_client(workspace_client: Any) -> Optional[Any]:
    api_client = getattr(workspace_client, "api_client", None)
    if callable(api_client):
        try:
            return api_client()
        except TypeError:
            return api_client
    return api_client


def _api_client_attr(workspace_client: Any, name: str) -> Optional[str]:
    api_client = _workspace_api_client(workspace_client)
    value = getattr(api_client, name, None) if api_client is not None else None
    return str(value) if value else None


def _workspace_api_do(
    workspace_client: Any,
    method: str,
    path: str,
    *,
    raw: bool = False,
) -> Any:
    api_client = _workspace_api_client(workspace_client)
    do = getattr(api_client, "do", None) if api_client is not None else None
    if not callable(do):
        return None
    try:
        return do(method, path=path, raw=raw)
    except TypeError:
        try:
            return do(method=method, path=path, raw=raw)
        except Exception:
            return None
    except Exception:
        return None


def _parse_workspace_config_response(response: Any) -> dict[str, Any]:
    if response is None:
        return {}
    if isinstance(response, Mapping):
        return {str(key): value for key, value in response.items()}
    if isinstance(response, (bytes, bytearray)):
        return _parse_workspace_config_text(response.decode("utf-8", errors="replace"))
    if isinstance(response, str):
        return _parse_workspace_config_text(response)

    read = getattr(response, "read", None)
    if callable(read):
        try:
            data = read()
        except Exception:
            return {}
        return _parse_workspace_config_response(data)
    return {}


def _parse_workspace_config_text(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if not stripped:
        return {}
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, Mapping):
        return {str(key): value for key, value in parsed.items()}

    values: dict[str, str] = {}
    for line in stripped.splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        for separator in ("=", ":"):
            if separator in item:
                key, value = item.split(separator, 1)
                values[key.strip()] = value.strip().strip('"')
                break
    return values


def _workspace_config_region(config: Mapping[str, Any]) -> Optional[str]:
    return _first_config_value(config, ("regionName", "awsRegion", "region"))


def _workspace_config_account_id(config: Mapping[str, Any]) -> Optional[str]:
    return _first_config_value(config, ("accountId", "account_id"))


def _account_workspace_region(config: Mapping[str, Any]) -> Optional[str]:
    return _first_config_value(config, ("aws_region", "location", "region"))


def _first_config_value(config: Mapping[str, Any], keys: Sequence[str]) -> Optional[str]:
    for key in keys:
        value = config.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _resolve_optional_secret(
    *,
    explicit: Optional[str],
    config: Optional[str],
    env_name: str,
) -> Optional[str]:
    return explicit or config or os.environ.get(env_name)


class _WorkspaceHeadersProvider:
    def __init__(
        self,
        authenticate: Callable[..., Mapping[str, Any]],
        table_name: str,
    ) -> None:
        self._authenticate = authenticate
        self._table_name = table_name

    def get_headers(self) -> list[tuple[str, str]]:
        headers = _call_workspace_authenticator(self._authenticate)
        if not isinstance(headers, Mapping):
            raise ValueError("workspace client authenticate() must return headers")
        normalized = {str(key).lower(): str(value) for key, value in headers.items()}
        normalized["x-databricks-zerobus-table-name"] = self._table_name
        return list(normalized.items())


def _workspace_headers_provider(
    workspace_client: Any,
    table_name: str,
) -> _WorkspaceHeadersProvider:
    return _WorkspaceHeadersProvider(
        _workspace_authenticator(workspace_client),
        table_name,
    )


def _workspace_authenticator(workspace_client: Any) -> Callable[..., Mapping[str, Any]]:
    config = getattr(workspace_client, "config", None)
    authenticate = getattr(config, "authenticate", None) if config is not None else None
    if callable(authenticate):
        return authenticate

    api_client = _workspace_api_client(workspace_client)
    config = getattr(api_client, "config", None) if api_client is not None else None
    authenticate = getattr(config, "authenticate", None) if config is not None else None
    if callable(authenticate):
        return authenticate

    raise ValueError("workspace_client.config.authenticate is required for Zerobus")


def _call_workspace_authenticator(
    authenticate: Callable[..., Mapping[str, Any]],
) -> Mapping[str, Any]:
    try:
        return authenticate()
    except TypeError:
        return authenticate(None)


@dataclass(frozen=True)
class _JsonlSinkHandle:
    sink: JsonlSink
    default_destination: Optional["_JsonlDestination"]
    route_destinations: Mapping[str, "_JsonlDestination"]
    record_count: int = 0

    def write(self, event: Mapping[str, Any], source: str) -> Optional[str]:
        if not _matches_sources(self.sink.sources, source):
            return None
        destination = self.default_destination or self.route_destinations.get(source)
        if destination is None:
            return None

        row = _event_record(event, self.sink.record)
        destination.handle.write(json.dumps(row, separators=(",", ":")) + "\n")
        object.__setattr__(self, "record_count", self.record_count + 1)
        if self.sink.flush_every and self.record_count % self.sink.flush_every == 0:
            self.flush()
        return _jsonl_sink_label(self.sink, destination.label, source)

    def flush(self) -> None:
        _flush_handles(self.default_destination, self.route_destinations)


def _open_jsonl_sink(sink: JsonlSink, stack: ExitStack) -> _JsonlSinkHandle:
    default_destination, route_destinations = _open_jsonl_destinations(
        sink.destinations, stack
    )
    return _JsonlSinkHandle(
        sink=sink,
        default_destination=default_destination,
        route_destinations=route_destinations,
    )


def _jsonl_sink_label(sink: JsonlSink, destination: str, source: str) -> str:
    if sink.sources is not None or isinstance(sink.destinations, Mapping):
        return f"{source} -> jsonl {destination}"
    return f"jsonl {destination}"


@dataclass
class _DatabricksVolumeSinkHandle:
    sink: DatabricksVolumeSink
    base_path: str
    run_id: str
    buffers: dict[str, list[str]] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    created_directories: set[str] = field(default_factory=set)

    def write(self, event: Mapping[str, Any], source: str) -> Optional[str]:
        if not _matches_sources(self.sink.sources, source):
            return None

        row = _event_record(event, self.sink.record)
        self.buffers.setdefault(source, []).append(
            json.dumps(row, separators=(",", ":")) + "\n"
        )
        if self.sink.flush_every and len(self.buffers[source]) >= self.sink.flush_every:
            self._upload_source(source)
        return self._label(source)

    def flush(self) -> None:
        for source in list(self.buffers):
            self._upload_source(source)

    def close(self) -> None:
        self.flush()

    def _upload_source(self, source: str) -> None:
        rows = self.buffers.get(source)
        if not rows:
            return

        counter = self.counters.get(source, 0)
        self.counters[source] = counter + 1
        directory = self.base_path
        file_path = (
            f"{directory}/{self.sink.file_prefix}-"
            f"{_safe_volume_segment(source)}-{counter:06d}.jsonl"
        )
        payload = "".join(rows).encode("utf-8")
        files = getattr(self.sink.workspace_client, "files", None)
        if files is None:
            raise ValueError("workspace_client must expose a files API")
        if directory not in self.created_directories:
            files.create_directory(directory)
            self.created_directories.add(directory)
        files.upload(file_path, io.BytesIO(payload), overwrite=self.sink.overwrite)
        rows.clear()

    def _label(self, source: str) -> str:
        return f"{source} -> volume {self.base_path}"


def _open_databricks_volume_sink(
    sink: DatabricksVolumeSink,
    stack: ExitStack,
    run_id: str,
) -> _DatabricksVolumeSinkHandle:
    handle = _DatabricksVolumeSinkHandle(
        sink=sink,
        base_path=_normalize_volume_path(sink.volume_path),
        run_id=run_id,
    )
    stack.callback(handle.close)
    return handle


@dataclass
class _ZerobusSinkHandle:
    sink: ZerobusSink
    stream: Any
    run_id: str
    generated_at: datetime
    batch: list[dict[str, Any]] = field(default_factory=list)
    acks: list[Any] = field(default_factory=list)

    def write(self, event: Mapping[str, Any], source: str) -> Optional[str]:
        if not _matches_sources(self.sink.sources, source):
            return None

        row = _event_to_zerobus_row(event, self.run_id, self.generated_at)
        self.batch.append(row)
        if self.sink.flush_every and len(self.batch) >= self.sink.flush_every:
            self.flush()
        return f"{source} -> zerobus {self.sink.table}"

    def flush(self) -> None:
        if self.batch:
            self._ingest_batch()
        while self.acks:
            ack = self.acks.pop(0)
            wait_for_ack = getattr(ack, "wait_for_ack", None)
            if callable(wait_for_ack):
                wait_for_ack()

    def _ingest_batch(self) -> None:
        batch = self.batch
        self.batch = []
        ingest_records = getattr(self.stream, "ingest_records", None)
        if callable(ingest_records):
            self._record_ack(ingest_records(batch))
            return

        ingest_records_offset = getattr(self.stream, "ingest_records_offset", None)
        if callable(ingest_records_offset):
            self._record_ack(ingest_records_offset(batch))
            return

        ingest_record = getattr(self.stream, "ingest_record")
        for row in batch:
            self._record_ack(ingest_record(row))

    def _record_ack(self, ack: Any) -> None:
        if ack is None:
            return
        if isinstance(ack, (list, tuple)):
            self.acks.extend(ack)
        else:
            self.acks.append(ack)

    def close(self) -> None:
        self.flush()
        close = getattr(self.stream, "close", None)
        if callable(close):
            close()


def _open_zerobus_sink(
    sink: ZerobusSink,
    stack: ExitStack,
    run_id: str,
    generated_at: datetime,
) -> _ZerobusSinkHandle:
    try:
        from zerobus.sdk.shared import (  # type: ignore[import-not-found]
            RecordType,
            StreamConfigurationOptions,
            TableProperties,
        )
        from zerobus.sdk.sync import ZerobusSdk  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "Zerobus sinks require `pip install databricks-zerobus-ingest-sdk`"
        ) from exc

    endpoint = _infer_zerobus_endpoint(sink.workspace_client, sink.region)
    workspace_url = _workspace_host(sink.workspace_client)
    client_id = _resolve_optional_secret(
        explicit=sink.client_id,
        config=_workspace_config_attr(sink.workspace_client, "client_id"),
        env_name=sink.client_id_env,
    )
    client_secret = _resolve_optional_secret(
        explicit=sink.client_secret,
        config=_workspace_config_attr(sink.workspace_client, "client_secret"),
        env_name=sink.client_secret_env,
    )
    if bool(client_id) != bool(client_secret):
        raise ValueError("set both zerobus client_id and client_secret, or neither")
    headers_provider = (
        None
        if client_id
        else _workspace_headers_provider(sink.workspace_client, sink.table)
    )
    sdk = ZerobusSdk(endpoint, workspace_url)
    options = StreamConfigurationOptions(record_type=RecordType.JSON)
    stream = sdk.create_stream(
        client_id or "",
        client_secret or "",
        TableProperties(sink.table),
        options,
        headers_provider=headers_provider,
    )
    handle = _ZerobusSinkHandle(
        sink=sink,
        stream=stream,
        run_id=run_id,
        generated_at=generated_at,
    )
    stack.callback(handle.close)
    return handle


def _open_sink(
    sink: Sink,
    stack: ExitStack,
    run_id: str,
    generated_at: datetime,
) -> Any:
    if isinstance(sink, JsonlSink):
        return _open_jsonl_sink(sink, stack)
    if isinstance(sink, DatabricksVolumeSink):
        return _open_databricks_volume_sink(sink, stack, run_id)
    if isinstance(sink, ZerobusSink):
        return _open_zerobus_sink(sink, stack, run_id, generated_at)
    raise TypeError(f"unsupported sink: {type(sink).__name__}")


def _normalize_until_time(value: Optional[Union[str, datetime]]) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    parsed = _parse_rfc3339(value)
    if parsed is None:
        raise ValueError(f"invalid until_time: {value}")
    return parsed


def _event_timestamp(event: Mapping[str, Any]) -> Optional[datetime]:
    envelope = event.get("envelope")
    if not isinstance(envelope, Mapping):
        return None
    timestamp = envelope.get("timestamp")
    return _parse_rfc3339(str(timestamp)) if timestamp is not None else None


def _run_stream_to_sinks(
    event_stream: EventStream,
    sinks: Sequence[Sink],
    *,
    max_events: Optional[int],
    events_per_second: Optional[float],
    until_time: Optional[Union[str, datetime]],
    time_scale: Optional[float],
    progress: Optional[ProgressReporter],
    progress_interval_seconds: float,
) -> StreamResult:
    if max_events is not None and max_events < 0:
        raise ValueError("max_events must be non-negative or None")
    if events_per_second is not None and events_per_second <= 0:
        raise ValueError("events_per_second must be greater than zero")
    if time_scale is not None and time_scale <= 0:
        raise ValueError("time_scale must be greater than zero")
    if events_per_second is not None and time_scale is not None:
        raise ValueError("set only one of events_per_second or time_scale")
    if progress_interval_seconds <= 0:
        raise ValueError("progress_interval_seconds must be greater than zero")
    if not sinks:
        raise ValueError("configure at least one sink before starting a stream")

    stop_at = _normalize_until_time(until_time)
    count = 0
    interval = 1.0 / events_per_second if events_per_second else None
    next_deadline = time.monotonic()
    replay_deadline = next_deadline
    last_event_time: Optional[datetime] = None
    started_at = next_deadline
    progress_tracker = _ProgressTracker(progress, progress_interval_seconds)
    run_id = f"seclog-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"
    generated_at = datetime.now(timezone.utc)

    with ExitStack() as stack:
        sink_handles = [
            _open_sink(sink, stack, run_id, generated_at)
            for sink in sinks
        ]
        try:
            while max_events is None or count < max_events:
                try:
                    event = next(event_stream)
                except StopIteration:
                    break

                event_time = _event_timestamp(event)
                if stop_at is not None and event_time is not None and event_time > stop_at:
                    break
                if time_scale is not None and event_time is not None:
                    if last_event_time is not None and event_time > last_event_time:
                        replay_deadline += (
                            event_time - last_event_time
                        ).total_seconds() / time_scale
                        sleep_seconds = replay_deadline - time.monotonic()
                        if sleep_seconds > 0:
                            time.sleep(sleep_seconds)
                    last_event_time = event_time

                source = event["envelope"]["source"]
                count += 1
                progress_tracker.record_event(source, event_time)

                sink_count = 0
                for sink_handle in sink_handles:
                    sink_label = sink_handle.write(event, source)
                    if sink_label is not None:
                        sink_count += 1
                        progress_tracker.record_sink(sink_label)
                if sink_count == 0:
                    raise ValueError(f"no sink configured for source {source}")

                progress_tracker.maybe_emit()

                if interval is not None:
                    next_deadline += interval
                    sleep_seconds = next_deadline - time.monotonic()
                    if sleep_seconds > 0:
                        time.sleep(sleep_seconds)
        finally:
            for sink_handle in sink_handles:
                sink_handle.flush()
            progress_tracker.finish()

    elapsed = max(time.monotonic() - started_at, 0.000_001)
    return StreamResult(
        events=count,
        elapsed_seconds=elapsed,
        events_per_second=count / elapsed,
    )


def _run_stream_to_jsonl_sinks(
    event_stream: EventStream,
    sinks: Sequence[JsonlSink],
    *,
    max_events: Optional[int],
    events_per_second: Optional[float],
    progress: Optional[ProgressReporter],
    progress_interval_seconds: float,
) -> StreamResult:
    return _run_stream_to_sinks(
        event_stream,
        sinks,
        max_events=max_events,
        events_per_second=events_per_second,
        until_time=None,
        time_scale=None,
        progress=progress,
        progress_interval_seconds=progress_interval_seconds,
    )


def _sink_stream_jsonl(
    event_stream: EventStream,
    destinations: JsonlDestination,
    *,
    max_events: Optional[int],
    payload_only: bool,
    flush_every: int,
    events_per_second: Optional[float],
    progress: Optional[ProgressReporter],
    progress_interval_seconds: float,
) -> int:
    sink = JsonlSink(
        destinations=destinations,
        record="payload" if payload_only else "event",
        flush_every=flush_every,
    )
    result = _run_stream_to_jsonl_sinks(
        event_stream,
        [sink],
        max_events=max_events,
        events_per_second=events_per_second,
        progress=progress,
        progress_interval_seconds=progress_interval_seconds,
    )
    return result.events


@dataclass(frozen=True)
class _JsonlDestination:
    handle: Any
    label: str


def _open_jsonl_destinations(
    destinations: JsonlDestination,
    stack: ExitStack,
) -> tuple[Optional[_JsonlDestination], dict[str, _JsonlDestination]]:
    if isinstance(destinations, Mapping):
        route_handles = {}
        for source, path in destinations.items():
            key = _normalize_source(str(source))
            if key in route_handles:
                raise ValueError(f"duplicate JSONL destination for source {key}")
            route_handles[key] = _open_jsonl_path(path, stack)
        return None, route_handles

    return _open_jsonl_path(destinations, stack), {}


def _open_jsonl_path(path: Union[str, Path], stack: ExitStack) -> _JsonlDestination:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    handle = stack.enter_context(output_path.open("w", encoding="utf-8"))
    return _JsonlDestination(handle=handle, label=str(path))


def _flush_handles(
    default_destination: Optional[_JsonlDestination],
    route_destinations: Mapping[str, _JsonlDestination],
) -> None:
    if default_destination is not None:
        default_destination.handle.flush()
    for destination in route_destinations.values():
        destination.handle.flush()


def _read_text(path: Union[str, Path]) -> str:
    return Path(path).read_text(encoding="utf-8")


def _multi_source_config(
    sources: Sequence[Mapping[str, Any]],
    *,
    population_config: Mapping[str, Any],
    identity_registry_path: Optional[Union[str, Path]],
    population_config_path: Optional[Union[str, Path]],
) -> dict[str, Any]:
    config: dict[str, Any] = {
        "type": "multi",
        "sources": list(sources),
    }
    if identity_registry_path is not None:
        config["identity_registry_path"] = str(identity_registry_path)
    elif population_config_path is not None:
        config["population_config_path"] = str(population_config_path)
    else:
        config["population_config"] = dict(population_config)
    return config


def _source_config(
    source: str,
    *,
    cloudtrail_regions: Sequence[str],
    cloudtrail_region_distribution: Sequence[float],
    databricks_account_id: str,
    databricks_workspace_id: str,
    databricks_baseline_events_per_actor: Optional[int],
    okta_org_id: str,
    okta_baseline_events_per_actor: Optional[int],
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
        }
        if databricks_baseline_events_per_actor is not None:
            config["baseline_events_per_actor"] = databricks_baseline_events_per_actor
    elif normalized == "okta_system_log":
        config = {
            "type": "okta",
            "org_id": okta_org_id,
        }
        if okta_baseline_events_per_actor is not None:
            config["baseline_events_per_actor"] = okta_baseline_events_per_actor
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
    "DatabricksVolumeSink",
    "ErrorRate",
    "EventStream",
    "ExplicitActor",
    "JsonlSink",
    "Population",
    "ProgressCounter",
    "ProgressReporter",
    "ProgressSnapshot",
    "Role",
    "ServiceProfile",
    "SourceRoute",
    "StreamPipeline",
    "StreamResult",
    "TimezoneWeight",
    "ZerobusSink",
    "default_config",
    "generate",
    "generate_from_config",
    "identities",
    "iter_events",
    "jsonl",
    "load_config",
    "load_population",
    "payloads",
    "sink_jsonl",
    "stream",
    "volume",
    "write_events_jsonl",
    "write_jsonl",
    "write_payloads_jsonl",
    "zerobus",
]
