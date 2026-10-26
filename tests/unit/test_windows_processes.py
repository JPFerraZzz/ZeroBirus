"""Real psutil data on Windows: what the backend actually produces for system processes."""

import importlib
import os

import pytest
from ctx_factory import typical_context

from zerobirus.core.models import ProcessInfo
from zerobirus.core.safety import is_protected_process

pytestmark = pytest.mark.windows

KERNEL_PSEUDO = ("System", "Registry", "Memory Compression")


def _listing() -> list[ProcessInfo]:
    processes = importlib.import_module("zerobirus.platform.windows.processes")
    return list(processes.list_processes(sample_cpu=False).items)


def test_system_pid_4_is_listed_and_protected() -> None:
    ctx = typical_context(system_root=os.environ["SYSTEMROOT"])
    by_pid = {p.pid: p for p in _listing()}
    system = by_pid[4]
    print(f"PID 4 as produced by the backend: {system!a}")
    assert system.name == "System"
    assert is_protected_process(system.name, system.path, ctx, pid=system.pid)


@pytest.mark.parametrize("name", KERNEL_PSEUDO)
def test_kernel_pseudo_processes_are_protected_as_the_backend_produces_them(name: str) -> None:
    ctx = typical_context(system_root=os.environ["SYSTEMROOT"])
    found = [p for p in _listing() if p.name == name]
    if not found:
        pytest.skip(f"{name} is not listed on this runner")
    for p in found:
        print(f"{name} as produced by the backend: {p!a}")
        assert is_protected_process(p.name, p.path, ctx, pid=p.pid)


def test_every_listed_system_named_process_is_judged_without_error() -> None:
    """Whatever psutil returns for every process must not make the safety check raise."""
    ctx = typical_context(system_root=os.environ["SYSTEMROOT"])
    for p in _listing():
        is_protected_process(p.name, p.path, ctx, pid=p.pid)


def test_system_exe_in_appdata_is_not_protected() -> None:
    ctx = typical_context(system_root=os.environ["SYSTEMROOT"])
    fake = r"C:\Users\Ana\AppData\Roaming\kzqpx\System.exe"
    assert not is_protected_process("System.exe", fake, ctx)
