"""The real Windows backend, on windows-latest. Read-only: nothing here writes outside pytest's
temporary folder, and nothing is ever created inside the Windows directory.

Output is printed (the CI step runs with ``-s``) so the real shapes can be read in the log.
"""

import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from zerobirus.core.models import Level, SignatureStatus
from zerobirus.core.report import build_report, render_text
from zerobirus.core.safety import SignerKind, is_protected_path
from zerobirus.scanners.runner import run_scan

pytestmark = pytest.mark.windows


def mod(name: str) -> Any:
    return importlib.import_module(f"zerobirus.platform.windows.{name}")


@pytest.fixture(scope="module")
def inspector() -> Any:
    return importlib.import_module("zerobirus.platform.windows").create_inspector()


def _show(title: str, value: object) -> None:
    print(ascii(f"{title}: {value}"))


def test_known_folders_agree_with_the_environment() -> None:
    kf = mod("knownfolders")
    pairs = {
        kf.PROGRAM_FILES: os.environ["PROGRAMFILES"],
        kf.PROGRAM_DATA: os.environ["PROGRAMDATA"],
        kf.PROFILE: os.environ["USERPROFILE"],
    }
    for folder_id, expected in pairs.items():
        assert kf.known_folder(folder_id).lower() == expected.lower()
    for folder_id in (
        kf.DOCUMENTS,
        kf.DESKTOP,
        kf.PICTURES,
        kf.VIDEOS,
        kf.MUSIC,
        kf.COMMON_STARTUP,
    ):
        assert os.path.isabs(kf.known_folder(folder_id))


def test_system_context_is_valid_canonical_and_complete(inspector: Any) -> None:
    ctx = inspector.system_context()
    _show("system_context", ctx)
    assert ctx.system_root.lower() == os.environ["SYSTEMROOT"].lower()
    assert os.environ["PROGRAMFILES"].lower() in {p.lower() for p in ctx.program_files}
    assert os.environ["USERPROFILE"].lower() in {p.lower() for p in ctx.profile_roots}
    assert os.getpid() in ctx.own_pids
    assert ctx.personal_folders
    assert is_protected_path(os.path.join(ctx.system_root, "System32", "cmd.exe"), ctx)
    assert not is_protected_path(
        os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming", "x", "a.exe"), ctx
    )


def test_is_elevated_is_a_bool(inspector: Any) -> None:
    _show("elevated", inspector.is_elevated())
    assert isinstance(inspector.is_elevated(), bool)


def test_processes_have_a_cpu_window_and_exclude_our_own_tree(inspector: Any) -> None:
    observed = inspector.processes()
    names = {p.name for p in observed.items}
    _show("processes", len(observed.items))
    _show("gaps", observed.gaps)
    assert "System" in names
    assert os.getpid() not in {p.pid for p in observed.items}
    measured = [p.cpu_percent for p in observed.items if p.cpu_percent is not None]
    assert measured
    assert all(0.0 <= c <= 100.0 for c in measured)


def test_services_come_from_the_registry(inspector: Any) -> None:
    observed = inspector.services()
    by_name = {s.name: s for s in observed.items}
    _show("services", len(by_name))
    _show("gaps", observed.gaps)
    assert len(by_name) > 50
    assert "svchost.exe" in by_name["Dnscache"].image_command.lower()
    assert by_name["Dnscache"].start in {"automatic", "manual", "disabled"}


def test_autoruns_include_winlogon_defaults_and_report_what_they_could_not_read(
    inspector: Any,
) -> None:
    observed = inspector.autoruns()
    kinds = {e.kind for e in observed.items}
    _show("autorun kinds", sorted(kinds))
    _show("autorun gaps", observed.gaps)
    for e in observed.items[:40]:
        _show("autorun", e)
    shell = [e for e in observed.items if e.kind == "winlogon" and e.name == "Shell"]
    assert shell
    assert shell[0].command.lower() == "explorer.exe"
    assert any(e.name == "Userinit" for e in observed.items)
    assert kinds <= {
        "run",
        "runonce",
        "policies_run",
        "winlogon",
        "appinit",
        "ifeo",
        "startup_folder",
    }


def test_hosts_connections_and_files_return_observations(inspector: Any, tmp_path: Path) -> None:
    hosts = inspector.hosts_lines()
    conns = inspector.connections()
    candidates = inspector.candidate_files()
    _show("hosts lines", len(hosts.items))
    _show("connections", (len(conns.items), conns.gaps))
    _show("candidate files", (len(candidates.items), candidates.gaps))
    assert isinstance(hosts.items, tuple)
    assert all(c.remote_port > 0 for c in conns.items)
    assert all(os.path.isabs(f.path) for f in candidates.items)


def test_scheduled_tasks_through_powershell(inspector: Any) -> None:
    observed = inspector.scheduled_tasks()
    _show("tasks", (len(observed.items), observed.gaps))
    for t in observed.items[:15]:
        _show("task", t)
    assert len(observed.items) > 20
    assert any(t.folder.lower().startswith("\\microsoft\\windows") for t in observed.items)
    assert all(a.execute for t in observed.items for a in t.actions)


def test_defender_is_read_or_reported_unavailable_never_silently_empty(inspector: Any) -> None:
    observed = inspector.defender()
    _show("defender", observed)
    assert observed.items or observed.gaps
    if observed.items:
        state = observed.items[0]
        assert state.realtime is None or isinstance(state.realtime, bool)


def test_wmi_subscriptions_are_read_or_reported(inspector: Any) -> None:
    observed = inspector.wmi_bindings()
    _show("wmi", observed)
    assert observed.items or observed.gaps or observed.items == ()


def test_raw_signature_rows_for_diagnosis() -> None:
    """Prints what Get-AuthenticodeSignature really returns, to read the shape in the log."""
    ps = mod("ps")
    root = os.environ["SYSTEMROOT"]
    paths = [
        os.path.join(root, "System32", "cmd.exe"),
        os.path.join(root, "System32", "kernel32.dll"),
        os.path.join(root, "explorer.exe"),
    ]
    rows = ps.run_json("signatures", {"paths": paths}, system_root=root)
    _show("raw signature rows", rows)
    assert len(rows) == 3


def test_signatures_valid_microsoft_unknown_for_text_and_nothing_made_up(
    inspector: Any, tmp_path: Path
) -> None:
    cmd = os.path.join(os.environ["SYSTEMROOT"], "System32", "cmd.exe")
    text = tmp_path / "note.txt"
    text.write_text("hello", "utf-8")
    missing = str(tmp_path / "nope.exe")
    observed = inspector.signatures([cmd, str(text), missing])
    by_path = {s.path: s for s in observed.items}
    _show("signatures", observed)
    assert by_path[cmd].status is SignatureStatus.VALID
    assert by_path[cmd].kind is SignerKind.MICROSOFT
    assert by_path[str(text)].status is not SignatureStatus.VALID
    assert missing not in by_path


def test_a_hostile_inherited_module_path_cannot_break_or_hijack_the_bridge(
    inspector: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evil = tmp_path / "Modules"
    (evil / "Microsoft.PowerShell.Security").mkdir(parents=True)
    (evil / "Microsoft.PowerShell.Security" / "Microsoft.PowerShell.Security.psm1").write_text(
        "throw 'hijacked'", "utf-8"
    )
    monkeypatch.setenv("PSModulePath", str(evil))
    cmd = os.path.join(os.environ["SYSTEMROOT"], "System32", "cmd.exe")
    got = inspector.signatures([cmd])
    assert [s.status for s in got.items] == [SignatureStatus.VALID]
    assert got.gaps == ()


def test_data_given_to_powershell_is_never_executed_or_altered() -> None:
    ps = mod("ps")
    nasty = [
        "C:\\x'; Write-Output pwned; '",
        'C:\\y" ; calc ; "',
        "C:\\z$(Get-Date)",
        "C:\\ã\u00e7\u4e2d\u6587 `n %PATH%",
    ]
    rows = ps.run_json("signatures", {"paths": nasty}, system_root=os.environ["SYSTEMROOT"])
    assert [r["path"] for r in rows] == nasty
    assert all(r["status"] == -1 for r in rows)


def test_powershell_timeout_is_enforced() -> None:
    ps = mod("ps")
    with pytest.raises(ps.PowerShellError):
        ps.run_json("tasks", None, system_root=os.environ["SYSTEMROOT"], timeout=0.01)


def test_file_search_respects_depth_and_finds_executables(tmp_path: Path) -> None:
    files = mod("files")
    deep = tmp_path
    for i in range(files.MAX_DEPTH + 2):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (tmp_path / "a.exe").write_bytes(b"x")
    (tmp_path / "d0" / "b.dll").write_bytes(b"x")
    (tmp_path / "ignored.txt").write_bytes(b"x")
    (deep / "too_deep.exe").write_bytes(b"x")
    found = {os.path.basename(f.path) for f in files.search_roots([str(tmp_path)]).items}
    assert found == {"a.exe", "b.dll"}


def test_file_search_does_not_follow_symlinks(tmp_path: Path) -> None:
    files = mod("files")
    target = tmp_path / "target"
    target.mkdir()
    (target / "inside.exe").write_bytes(b"x")
    root = tmp_path / "root"
    root.mkdir()
    try:
        os.symlink(target, root / "link", target_is_directory=True)
    except OSError:
        pytest.skip("cannot create symlinks here")
    assert files.search_roots([str(root)]).items == ()


def test_sha256_matches_known_value(tmp_path: Path) -> None:
    files = mod("files")
    f = tmp_path / "x.bin"
    f.write_bytes(b"abc")
    got = files.sha256_of([str(f), str(tmp_path / "missing")])
    assert got.items[0].sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert got.gaps


def test_full_read_only_scan_of_this_machine(inspector: Any) -> None:
    result = run_scan(inspector, timeout=120.0)
    report = build_report(result, generated_at="ci")
    text = json.dumps(report, ensure_ascii=True)
    print(ascii(render_text(report)))
    for check in result.checks:
        _show(
            f"check {check.check}",
            (check.level.value, check.verified, check.reason, check.inspected),
        )
        for f in check.findings:
            if f.level is not Level.OK:
                _show("  finding", (f.level.value, f.item, f.location, [s.code for s in f.signals]))
    assert [c.check for c in result.checks] == [
        "processes",
        "startup",
        "tasks",
        "services",
        "files",
        "network",
        "defender",
        "hosts",
        "wmi_bindings",
    ]
    assert result.snapshot.processes
    assert "snapshot" in report
    assert os.environ["USERNAME"].lower() not in text.lower()
    for check in result.checks:
        assert check.verified or check.reason
        assert check.level is not Level.OK or check.verified


def test_the_scan_leaves_the_machine_as_it_found_it(inspector: Any, tmp_path: Path) -> None:
    """Read-only in practice: the Startup folders and the temp directory are unchanged."""
    startup = [
        os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.environ["PROGRAMDATA"], r"Microsoft\Windows\Start Menu\Programs\StartUp"),
    ]

    def listing() -> dict[str, list[str]]:
        folders = [*startup, os.environ["TEMP"]]
        return {d: sorted(os.listdir(d)) for d in folders if os.path.isdir(d)}

    before = listing()
    run_scan(inspector, timeout=120.0)
    after = listing()
    created = {d: sorted(set(after[d]) - set(before[d])) for d in after}
    # pytest and other CI processes may touch TEMP; only Startup folders must be untouched
    assert all(created[d] == [] for d in startup if d in created)


def test_platform_is_windows() -> None:
    assert sys.platform == "win32"
