"""Everything an Inspector observed, as plain data.

A snapshot is the unit of exchange between the backend and the rest of the program: the
Windows backend produces it, the fake backend replays it, and a scan report carries it.
That is what turns a report from a real machine into a golden fixture.
"""

from __future__ import annotations

import types
import typing
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from typing import Any, cast

from zerobirus.core.models import (
    AutorunEntry,
    ConnectionInfo,
    DefenderState,
    FileCandidate,
    FileHash,
    ProcessInfo,
    ServiceInfo,
    Signature,
    TaskInfo,
    WmiBinding,
)
from zerobirus.core.safety import SystemContext

SCHEMA_VERSION = 1

SECTIONS = (
    "processes",
    "autoruns",
    "tasks",
    "services",
    "connections",
    "defender",
    "hosts",
    "wmi_bindings",
    "files",
    "signatures",
    "hashes",
)


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Observed state. ``gaps`` maps a section name to what could not be read in it."""

    elevated: bool
    system: SystemContext
    processes: tuple[ProcessInfo, ...] = ()
    autoruns: tuple[AutorunEntry, ...] = ()
    tasks: tuple[TaskInfo, ...] = ()
    services: tuple[ServiceInfo, ...] = ()
    connections: tuple[ConnectionInfo, ...] = ()
    defender: tuple[DefenderState, ...] = ()
    hosts: tuple[str, ...] = ()
    wmi_bindings: tuple[WmiBinding, ...] = ()
    files: tuple[FileCandidate, ...] = ()
    signatures: tuple[Signature, ...] = ()
    hashes: tuple[FileHash, ...] = ()
    gaps: dict[str, tuple[str, ...]] = field(default_factory=dict[str, tuple[str, ...]])


def _seq(value: Any) -> list[Any]:
    return list(value)


def _items(value: Any) -> list[tuple[Any, Any]]:
    return list(value.items())


def to_jsonable(obj: object) -> Any:
    """Dataclasses, enums and tuples to plain JSON types."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (set, frozenset)):
        return sorted(to_jsonable(x) for x in cast("set[Any]", obj))
    if isinstance(obj, (tuple, list)):
        return [to_jsonable(x) for x in cast("list[Any]", obj)]
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in _items(obj)}
    return obj


def from_jsonable[T](cls: type[T], data: Any) -> T:
    """Inverse of ``to_jsonable`` for the types used in this module. Strict about types."""
    return _decode(cls, data)  # type: ignore[no-any-return]


def _decode(tp: Any, data: Any) -> Any:
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)
    if origin is typing.Union or origin is types.UnionType:
        if data is None and type(None) in args:
            return None
        (inner,) = (a for a in args if a is not type(None))
        return _decode(inner, data)
    if origin is tuple:
        if not isinstance(data, list):
            raise TypeError(f"expected a list, got {type(data).__name__}")
        return tuple(_decode(args[0], x) for x in _seq(data))
    if origin is frozenset:
        return frozenset(_decode(args[0], x) for x in data)
    if origin is dict:
        if not isinstance(data, dict):
            raise TypeError(f"expected an object, got {type(data).__name__}")
        return {_decode(args[0], k): _decode(args[1], v) for k, v in data.items()}
    if isinstance(tp, type) and issubclass(tp, Enum):
        return tp(data)
    if isinstance(tp, type) and is_dataclass(tp):
        if not isinstance(data, dict):
            raise TypeError(f"expected an object for {tp.__name__}")
        hints = typing.get_type_hints(tp)
        known = {f.name for f in fields(tp)}
        raw = cast("dict[str, Any]", data)
        unknown = set(raw) - known
        if unknown:
            raise TypeError(f"{tp.__name__}: unknown fields {sorted(unknown)}")
        return tp(**{k: _decode(hints[k], v) for k, v in raw.items()})
    if tp is float and isinstance(data, int) and not isinstance(data, bool):
        return float(data)
    if tp is Any:
        return data
    if tp is not bool and isinstance(data, bool) and tp in (int, float):
        raise TypeError(f"expected {tp!r}, got bool")
    if not isinstance(data, tp):
        raise TypeError(f"expected {tp!r}, got {type(data).__name__}")
    return data


def snapshot_to_dict(snapshot: Snapshot) -> dict[str, Any]:
    data: dict[str, Any] = to_jsonable(snapshot)
    data["schema_version"] = SCHEMA_VERSION
    return data


def snapshot_from_dict(data: dict[str, Any]) -> Snapshot:
    data = dict(data)
    version = data.pop("schema_version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise ValueError(f"unsupported snapshot schema version {version}")
    return from_jsonable(Snapshot, data)
