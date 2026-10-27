"""The Windows implementation of ``SystemOps``: does exactly what the engine asks.

No decisions here (the engine has already authorised and re-checked every item). Native APIs
where they exist: ``winreg`` for registry values, ``psutil`` for processes, plain file calls
for the hosts file and the quarantine. PowerShell only for restore points, scheduled tasks,
services, WMI, Defender and the firewall, always through ``ps.run_json`` with the parameters
as JSON data.
"""

from __future__ import annotations

import base64
import os
import sys
import time
import winreg
from typing import Any, cast

import psutil

from zerobirus.core.plan import EXCLUSION_KINDS, ActionType, PlanItem
from zerobirus.platform.windows import ps
from zerobirus.platform.windows.paths import canonical_path
from zerobirus.remediation.ops import LocalFileOps

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

HOSTS_MARK = "# ZeroBirus"
HOSTS_MAX_BYTES = 1024 * 1024
_RESTORE_TIMEOUT = 300.0
_KILL_WAIT = 5.0


def _first(out: ps.PsOutput) -> dict[str, Any]:
    items: Any = out.items
    head: Any = items
    if isinstance(items, list):
        head = items[0] if items else None  # pyright: ignore[reportUnknownVariableType]
    return cast("dict[str, Any]", head) if isinstance(head, dict) else {}


class WindowsOps(LocalFileOps):
    def __init__(self, system_root: str) -> None:
        self._root = system_root
        self._seen: dict[int, str] = {}

    # PowerShell ------------------------------------------------------------------------

    def _call(self, action: str, **params: Any) -> Any:
        out = ps.run_json("remediate", {"action": action, **params}, system_root=self._root)
        first = _first(out)
        if not first:
            raise RuntimeError("o PowerShell não devolveu resultado")
        if not first.get("ok"):
            raise RuntimeError(str(first.get("data") or "a ação falhou"))
        return first.get("data")

    # restore point ---------------------------------------------------------------------

    def create_restore_point(self, description: str) -> str | None:
        try:
            out = ps.run_json(
                "remediate",
                {"action": "restore_point", "description": description},
                system_root=self._root,
                timeout=_RESTORE_TIMEOUT,
            )
        except ps.PowerShellError as exc:
            return str(exc)
        first = _first(out)
        if first.get("ok"):
            return None
        reason = str(first.get("data") or "")
        return reason or "o Windows não criou o ponto de restauro (proteção do sistema desativada?)"

    # processes -------------------------------------------------------------------------

    def process_image(self, pid: int) -> str | None:
        try:
            proc = psutil.Process(pid)
            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                return None
            try:
                image = canonical_path(proc.exe())
            except (psutil.AccessDenied, OSError):
                return ""
        except psutil.NoSuchProcess:
            return None
        self._seen[pid] = image
        return image

    def terminate(self, pid: int) -> None:
        try:
            proc = psutil.Process(pid)
            now = canonical_path(proc.exe())
        except psutil.NoSuchProcess:
            return
        if self._seen.get(pid) != now:
            raise RuntimeError("o número do processo passou para outro programa")
        try:
            proc.terminate()
            proc.wait(_KILL_WAIT)
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(_KILL_WAIT)
        except psutil.NoSuchProcess:
            return

    # registry --------------------------------------------------------------------------

    @staticmethod
    def _reg(item: PlanItem) -> tuple[int, str, int]:
        root, key = item.param("root"), item.param("key")
        view = winreg.KEY_WOW64_32KEY if item.param("view") == "32" else winreg.KEY_WOW64_64KEY
        if root == "HKLM":
            return winreg.HKEY_LOCAL_MACHINE, key, view
        sid = root.split("\\", 1)[1]
        return winreg.HKEY_USERS, f"{sid}\\{key}", view

    def _reg_read(self, item: PlanItem) -> tuple[Any, int] | None:
        hive, sub, view = self._reg(item)
        try:
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | view) as k:
                data, kind = winreg.QueryValueEx(k, item.param("value"))
                return data, kind
        except FileNotFoundError:
            return None

    # undo state for everything that is not a file or process -----------------------------

    def capture(self, item: PlanItem) -> dict[str, Any]:
        a = item.action
        if a is ActionType.REMOVE_REGISTRY_VALUE:
            got = self._reg_read(item)
            if got is None:
                raise LookupError("o valor de registo não existe")
            data, kind = got
            if isinstance(data, bytes):
                return {"type": kind, "hex": data.hex()}
            return {"type": kind, "data": data}
        if a is ActionType.REMOVE_TASK:
            xml = self._call("task_capture", name=item.param("name"), folder=item.param("folder"))
            return {"xml": xml}
        if a is ActionType.DISABLE_SERVICE:
            data = self._call("service_state", name=item.param("name"))
            return {"start": data["start"], "state": data["state"]}
        if a is ActionType.REMOVE_WMI_BINDING:
            data = self._call("wmi_capture", **self._wmi(item))
            return {"filter": data["filter"], "consumer": data["consumer"]}
        if a is ActionType.REMOVE_HOSTS_LINE:
            raw = self._hosts_bytes()
            lines = [
                line
                for line in raw.decode("utf-8", "replace").splitlines()
                if line.strip() == item.param("line").strip()
            ]
            return {"backup_b64": base64.b64encode(raw).decode("ascii"), "lines": lines}
        if a is ActionType.ADD_HOSTS_BLOCK:
            return {"line": self._block_line(item)}
        return {"present": True}

    @staticmethod
    def _wmi(item: PlanItem) -> dict[str, str]:
        return {
            "filter": item.param("filter"),
            "consumer": item.param("consumer"),
            "consumer_class": item.param("consumer_class"),
        }

    # changes ---------------------------------------------------------------------------

    def perform(self, item: PlanItem) -> None:
        a = item.action
        if a is ActionType.REMOVE_REGISTRY_VALUE:
            hive, sub, view = self._reg(item)
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_SET_VALUE | view) as k:
                winreg.DeleteValue(k, item.param("value"))
        elif a is ActionType.REMOVE_TASK:
            self._call("task_remove", name=item.param("name"), folder=item.param("folder"))
        elif a is ActionType.DISABLE_SERVICE:
            self._call("service_disable", name=item.param("name"))
        elif a is ActionType.REMOVE_WMI_BINDING:
            self._call("wmi_remove", **self._wmi(item))
        elif a is ActionType.REMOVE_DEFENDER_EXCLUSION:
            self._call(
                "defender_remove",
                kind=EXCLUSION_KINDS[item.param("exclusion_kind")],
                value=item.param("value"),
            )
        elif a is ActionType.REMOVE_HOSTS_LINE:
            wanted = item.param("line").strip()
            raw = self._hosts_bytes()
            kept = [
                x
                for x in raw.splitlines(keepends=True)
                if x.decode("utf-8", "replace").strip() != wanted
            ]
            self._hosts_write(b"".join(kept))
        elif a is ActionType.ADD_HOSTS_BLOCK:
            raw = self._hosts_bytes()
            if raw and not raw.endswith(b"\n"):
                raw += b"\r\n"
            self._hosts_write(raw + (self._block_line(item) + "\r\n").encode("ascii"))
        elif a is ActionType.ADD_FIREWALL_BLOCK:
            self._call("firewall_add", address=item.param("address"))
        else:
            raise ValueError("ação desconhecida")

    def verify(self, item: PlanItem) -> bool:
        a = item.action
        if a is ActionType.KILL_PROCESS:
            pid = int(item.param("pid"))
            image = self.process_image(pid)
            return image is None or (
                bool(item.param("path")) and image.lower() != item.param("path").lower()
            )
        if a is ActionType.REMOVE_REGISTRY_VALUE:
            return self._reg_read(item) is None
        if a is ActionType.REMOVE_TASK:
            return not self._call(
                "task_exists", name=item.param("name"), folder=item.param("folder")
            )
        if a is ActionType.DISABLE_SERVICE:
            data = self._call("service_state", name=item.param("name"))
            return str(data["start"]) == "Disabled" and str(data["state"]) == "Stopped"
        if a is ActionType.REMOVE_WMI_BINDING:
            return not self._call("wmi_exists", **self._wmi(item))
        if a is ActionType.REMOVE_DEFENDER_EXCLUSION:
            return not self._call(
                "defender_has",
                kind=EXCLUSION_KINDS[item.param("exclusion_kind")],
                value=item.param("value"),
            )
        if a is ActionType.REMOVE_HOSTS_LINE:
            wanted = item.param("line").strip()
            lines = self._hosts_bytes().decode("utf-8", "replace").splitlines()
            return wanted not in (x.strip() for x in lines)
        if a is ActionType.ADD_HOSTS_BLOCK:
            return self._block_line(item) in (
                x.strip() for x in self._hosts_bytes().decode("utf-8", "replace").splitlines()
            )
        if a is ActionType.ADD_FIREWALL_BLOCK:
            return bool(self._call("firewall_has", address=item.param("address")))
        return False

    def restore(self, item: PlanItem, saved: dict[str, Any]) -> None:
        a = item.action
        if a is ActionType.REMOVE_REGISTRY_VALUE:
            hive, sub, view = self._reg(item)
            data: Any = bytes.fromhex(saved["hex"]) if "hex" in saved else saved["data"]
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_SET_VALUE | view) as k:
                winreg.SetValueEx(k, item.param("value"), 0, int(saved["type"]), data)
        elif a is ActionType.REMOVE_TASK:
            self._call(
                "task_restore",
                name=item.param("name"),
                folder=item.param("folder"),
                xml=saved["xml"],
            )
        elif a is ActionType.DISABLE_SERVICE:
            self._call("service_restore", name=item.param("name"), start=saved["start"])
        elif a is ActionType.REMOVE_WMI_BINDING:
            self._call(
                "wmi_restore",
                consumer_class=item.param("consumer_class"),
                filter_props=saved["filter"],
                consumer_props=saved["consumer"],
            )
        elif a is ActionType.REMOVE_DEFENDER_EXCLUSION:
            self._call(
                "defender_add",
                kind=EXCLUSION_KINDS[item.param("exclusion_kind")],
                value=item.param("value"),
            )
        elif a is ActionType.REMOVE_HOSTS_LINE:
            raw = self._hosts_bytes()
            present = {x.strip() for x in raw.decode("utf-8", "replace").splitlines()}
            back = [x for x in saved["lines"] if x.strip() not in present]
            if back:
                if raw and not raw.endswith(b"\n"):
                    raw += b"\r\n"
                self._hosts_write(raw + "".join(x + "\r\n" for x in back).encode("utf-8"))
        elif a is ActionType.ADD_HOSTS_BLOCK:
            wanted = saved["line"]
            kept = [
                x
                for x in self._hosts_bytes().splitlines(keepends=True)
                if x.decode("utf-8", "replace").strip() != wanted
            ]
            self._hosts_write(b"".join(kept))
        elif a is ActionType.ADD_FIREWALL_BLOCK:
            self._call("firewall_remove", address=item.param("address"))

    # hosts file ------------------------------------------------------------------------

    def _hosts_path(self) -> str:
        return os.path.join(self._root, "System32", "drivers", "etc", "hosts")

    def _hosts_bytes(self) -> bytes:
        path = self._hosts_path()
        if os.path.getsize(path) > HOSTS_MAX_BYTES:
            raise RuntimeError("o ficheiro hosts é grande demais para ser alterado com segurança")
        with open(path, "rb") as fh:
            return fh.read()

    def _hosts_write(self, data: bytes) -> None:
        with open(self._hosts_path(), "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

    @staticmethod
    def _block_line(item: PlanItem) -> str:
        return f"0.0.0.0 {item.param('host').lower()} {HOSTS_MARK}"


def wait_gone(pid: int, seconds: float = 3.0) -> bool:
    """True when the process no longer exists (small helper for tests on Windows)."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not psutil.pid_exists(pid):
            return True
        time.sleep(0.1)
    return not psutil.pid_exists(pid)
