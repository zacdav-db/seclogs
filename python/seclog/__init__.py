"""Python bindings for seclog.

The public API is intentionally small:

    import seclog

    events = seclog.generate(max_events=1000)
    okta_payloads = seclog.payloads(sources=["okta"], max_events=100)
    identities = seclog.identities(seclog.Population(size=50))

Generated events are dictionaries with the normalized seclog envelope and the
source-native payload. Use ``payloads`` when loading raw CloudTrail,
Databricks audit, or Okta records into a downstream system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
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


def generate(
    *,
    max_events: int = 100,
    sources: Sequence[str] = DEFAULT_SOURCES,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    config: Optional[Mapping[str, Any]] = None,
    **config_kwargs: Any,
) -> list[dict[str, Any]]:
    """Generate normalized seclog events as dictionaries."""

    return list(
        iter_events(
            max_events=max_events,
            sources=sources,
            population=population,
            config=config,
            **config_kwargs,
        )
    )


def iter_events(
    *,
    max_events: int = 100,
    sources: Sequence[str] = DEFAULT_SOURCES,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    config: Optional[Mapping[str, Any]] = None,
    **config_kwargs: Any,
) -> Iterator[dict[str, Any]]:
    """Iterate generated normalized events."""

    selected_config = (
        dict(config)
        if config is not None
        else default_config(sources=sources, population=population, **config_kwargs)
    )
    for event_json in _native_module().generate_events_json(
        json.dumps(selected_config), max_events
    ):
        yield json.loads(event_json)


def payloads(
    *,
    max_events: int = 100,
    sources: Sequence[str] = DEFAULT_SOURCES,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    config: Optional[Mapping[str, Any]] = None,
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
            **config_kwargs,
        )
    ]


def identities(
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
) -> list[dict[str, Any]]:
    """Generate the shared identity registry implied by a population config."""

    population_dict = _population_to_dict(population)
    return [
        json.loads(identity_json)
        for identity_json in _native_module().generate_identities_json(
            json.dumps(population_dict)
        )
    ]


def write_jsonl(
    path: Union[str, Path],
    *,
    max_events: int = 100,
    payload_only: bool = False,
    sources: Sequence[str] = DEFAULT_SOURCES,
    population: Optional[Union[Population, Mapping[str, Any]]] = None,
    config: Optional[Mapping[str, Any]] = None,
    **config_kwargs: Any,
) -> int:
    """Write generated events or source-native payloads to a JSONL file."""

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0

    with output_path.open("w", encoding="utf-8") as handle:
        for event in iter_events(
            max_events=max_events,
            sources=sources,
            population=population,
            config=config,
            **config_kwargs,
        ):
            row = event["payload"] if payload_only else event
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")
            count += 1

    return count


def generate_from_config(
    config: Mapping[str, Any],
    *,
    max_events: int = 100,
) -> list[dict[str, Any]]:
    """Generate events from an explicit seclog config dictionary."""

    return generate(config=config, max_events=max_events)


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
    "payloads",
    "write_jsonl",
]
