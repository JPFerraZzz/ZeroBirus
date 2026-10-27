"""In-memory SystemOps: a tiny fake machine for tests and ``--demo`` (nothing real is touched)."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from zerobirus.core.models import TempEntry
from zerobirus.core.plan import EXCLUSION_KINDS, ActionType, PlanItem
from zerobirus.core.safety import normalize_windows_path
from zerobirus.core.snapshot import Snapshot
from zerobirus.remediation.ops import FileKind


def _n(path: str) -> str:
    return normalize_windows_path(path)


@dataclass(slots=True)
class _Node:
    kind: FileKind
    content: str = ""
    has_inner_link: bool = False


@dataclass(slots=True)
class FakeOps:
    """A fake machine. Flags let a test make things fail the way a real PC does."""

    restore_point_error: str | None = None
    files: dict[str, _Node] = field(default_factory=dict[str, _Node])
    processes: dict[int, str] = field(default_factory=dict[int, str])
    registry: dict[tuple[str, str, str], str] = field(
        default_factory=dict[tuple[str, str, str], str]
    )
    tasks: dict[tuple[str, str], str] = field(default_factory=dict[tuple[str, str], str])
    services: dict[str, dict[str, Any]] = field(default_factory=dict[str, dict[str, Any]])
    wmi: set[tuple[str, str]] = field(default_factory=set[tuple[str, str]])
    exclusions: set[tuple[str, str]] = field(default_factory=set[tuple[str, str]])
    hosts: list[str] = field(default_factory=list[str])
    firewall: set[str] = field(default_factory=set[str])
    locked: set[str] = field(default_factory=set[str])
    stubborn_pids: set[int] = field(default_factory=set[int])
    aliased: set[str] = field(default_factory=set[str])
    calls: list[str] = field(default_factory=list[str])

    @classmethod
    def from_snapshot(
        cls, snap: Snapshot, temp: Iterable[TempEntry] = (), **kwargs: Any
    ) -> FakeOps:
        ops = cls(**kwargs)
        for p in snap.processes:
            ops.processes[p.pid] = p.path or ""
            if p.path and p.path[1:3] == ":\\":
                ops.add_file(p.path)
        for f in snap.files:
            ops.add_file(f.path)
        for a in snap.autoruns:
            if a.kind == "startup_folder" and a.path:
                ops.add_file(a.path)
            m = a.source.rsplit(" (", 1)[0]
            root, _, key = m.partition("\\Software\\")
            if a.kind in ("run", "runonce", "policies_run"):
                ops.registry[(root, "Software\\" + key, a.name.lower())] = a.command
        for t in snap.tasks:
            ops.tasks[(t.folder, t.name)] = f"<Task name='{t.name}'/>"
        for s in snap.services:
            ops.services[s.name] = {"start": s.start, "running": True}
        for w in snap.wmi_bindings:
            ops.wmi.add((w.filter_name, w.consumer_name))
        for d in snap.defender:
            for kind, vals in (
                ("path", d.exclusion_paths),
                ("extension", d.exclusion_extensions),
                ("process", d.exclusion_processes),
                ("ip", d.exclusion_ips),
            ):
                ops.exclusions.update((kind, v) for v in vals or ())
        ops.hosts = list(snap.hosts)
        for t_ in temp:
            ops.add_file(t_.path, is_dir=t_.is_dir)
        return ops

    def add_file(self, path: str, *, is_dir: bool = False, content: str | None = None) -> None:
        self.files[_n(path)] = _Node("dir" if is_dir else "file", content or "data:" + _n(path))

    def add_link(self, path: str) -> None:
        self.files[_n(path)] = _Node("link")

    # SystemOps ------------------------------------------------------------------------

    def create_restore_point(self, description: str) -> str | None:
        self.calls.append("restore_point")
        return self.restore_point_error

    def process_image(self, pid: int) -> str | None:
        return self.processes.get(pid)

    def terminate(self, pid: int) -> None:
        self.calls.append(f"kill:{pid}")
        if pid not in self.stubborn_pids:
            self.processes.pop(pid, None)

    def file_kind(self, path: str) -> FileKind:
        node = self.files.get(_n(path))
        return node.kind if node else "missing"

    def resolves_to_itself(self, path: str) -> bool:
        return _n(path) not in self.aliased

    def tree_has_link(self, path: str) -> bool:
        node = self.files.get(_n(path))
        return bool(node and node.has_inner_link)

    def fingerprint(self, path: str) -> str | None:
        node = self.files.get(_n(path))
        return hashlib.sha256(node.content.encode()).hexdigest() if node else None

    def move(self, src: str, dest: str) -> None:
        self.calls.append(f"move:{_n(src)}")
        if _n(src) in self.locked:
            raise PermissionError("o ficheiro está a ser usado por outro processo")
        if _n(dest) in self.files:
            raise FileExistsError(dest)
        self.files[_n(dest)] = self.files.pop(_n(src))

    def delete_tree(self, path: str) -> None:
        self.calls.append(f"delete:{_n(path)}")
        self.files.pop(_n(path), None)

    def capture(self, item: PlanItem) -> dict[str, Any]:
        a = item.action
        if a is ActionType.REMOVE_REGISTRY_VALUE:
            key = self._reg_key(item)
            if key not in self.registry:
                raise LookupError("o valor de registo não existe")
            return {"data": self.registry[key]}
        if a is ActionType.REMOVE_TASK:
            return {"xml": self.tasks[(item.param("folder"), item.param("name"))]}
        if a is ActionType.DISABLE_SERVICE:
            return dict(self.services[item.param("name")])
        if a is ActionType.REMOVE_HOSTS_LINE:
            return {"hosts": list(self.hosts)}
        return {"present": True}

    def perform(self, item: PlanItem) -> None:
        self.calls.append(f"perform:{item.action.value}")
        a = item.action
        if a is ActionType.REMOVE_REGISTRY_VALUE:
            self.registry.pop(self._reg_key(item), None)
        elif a is ActionType.REMOVE_TASK:
            self.tasks.pop((item.param("folder"), item.param("name")), None)
        elif a is ActionType.DISABLE_SERVICE:
            self.services[item.param("name")] = {"start": "disabled", "running": False}
        elif a is ActionType.REMOVE_WMI_BINDING:
            self.wmi.discard((item.param("filter"), item.param("consumer")))
        elif a is ActionType.REMOVE_DEFENDER_EXCLUSION:
            self.exclusions.discard(
                (EXCLUSION_KINDS[item.param("exclusion_kind")], item.param("value"))
            )
        elif a is ActionType.REMOVE_HOSTS_LINE:
            self.hosts = [x for x in self.hosts if x.strip() != item.param("line").strip()]
        elif a is ActionType.ADD_HOSTS_BLOCK:
            self.hosts.append(f"0.0.0.0 {item.param('host')} # ZeroBirus")
        elif a is ActionType.ADD_FIREWALL_BLOCK:
            self.firewall.add(item.param("address"))

    def verify(self, item: PlanItem) -> bool:
        a = item.action
        if a is ActionType.KILL_PROCESS:
            return int(item.param("pid")) not in self.processes
        if a is ActionType.REMOVE_REGISTRY_VALUE:
            return self._reg_key(item) not in self.registry
        if a is ActionType.REMOVE_TASK:
            return (item.param("folder"), item.param("name")) not in self.tasks
        if a is ActionType.DISABLE_SERVICE:
            svc = self.services.get(item.param("name"), {})
            return svc.get("start") == "disabled" and not svc.get("running")
        if a is ActionType.REMOVE_WMI_BINDING:
            return (item.param("filter"), item.param("consumer")) not in self.wmi
        if a is ActionType.REMOVE_DEFENDER_EXCLUSION:
            return (
                EXCLUSION_KINDS[item.param("exclusion_kind")],
                item.param("value"),
            ) not in self.exclusions
        if a is ActionType.REMOVE_HOSTS_LINE:
            return item.param("line").strip() not in (x.strip() for x in self.hosts)
        if a is ActionType.ADD_HOSTS_BLOCK:
            return any(item.param("host") in x and "ZeroBirus" in x for x in self.hosts)
        if a is ActionType.ADD_FIREWALL_BLOCK:
            return item.param("address") in self.firewall
        return False

    def restore(self, item: PlanItem, saved: dict[str, Any]) -> None:
        a = item.action
        if a is ActionType.REMOVE_REGISTRY_VALUE:
            self.registry[self._reg_key(item)] = saved["data"]
        elif a is ActionType.REMOVE_TASK:
            self.tasks[(item.param("folder"), item.param("name"))] = saved["xml"]
        elif a is ActionType.DISABLE_SERVICE:
            self.services[item.param("name")] = dict(saved)
        elif a is ActionType.REMOVE_WMI_BINDING:
            self.wmi.add((item.param("filter"), item.param("consumer")))
        elif a is ActionType.REMOVE_DEFENDER_EXCLUSION:
            self.exclusions.add(
                (EXCLUSION_KINDS[item.param("exclusion_kind")], item.param("value"))
            )
        elif a is ActionType.REMOVE_HOSTS_LINE:
            self.hosts = list(saved["hosts"])
        elif a is ActionType.ADD_HOSTS_BLOCK:
            self.hosts = [x for x in self.hosts if "ZeroBirus" not in x]
        elif a is ActionType.ADD_FIREWALL_BLOCK:
            self.firewall.discard(item.param("address"))

    @staticmethod
    def _reg_key(item: PlanItem) -> tuple[str, str, str]:
        return (item.param("root"), item.param("key"), item.param("value").lower())
