"""Whole-drive Defender exclusions, and SUSPEITO findings no named threat explains."""

from collections.abc import Callable

import pytest

from zerobirus.core.diagnosis import UNCLASSIFIED_KIND, diagnose, overall_level
from zerobirus.core.models import (
    AutorunEntry,
    ConnectionInfo,
    DefenderState,
    Level,
    ProcessInfo,
    Signature,
    SignatureStatus,
    TaskAction,
    TaskInfo,
)
from zerobirus.core.report import build_report, render_text
from zerobirus.core.safety import SignerKind
from zerobirus.core.snapshot import Snapshot
from zerobirus.platform.fake import FakeInspector, load_fixture
from zerobirus.scanners.runner import ScanResult, run_scan

SYSTEM = load_fixture("clean_pc").system
DROP = r"C:\Users\Ana\AppData\Roaming\kzqpx\a.exe"
TEMP_EXE = r"C:\Users\Ana\AppData\Local\Temp\b.exe"
PROGRAMDATA_EXE = r"C:\ProgramData\GitHub\agent\agent.exe"
WHOLE_DRIVE = DefenderState(True, True, False, 1, (), ("C:\\", "D:\\"), (), (), ())
UNSIGNED = tuple(
    Signature(p, SignatureStatus.UNSIGNED, SignerKind.UNSIGNED, "")
    for p in (DROP, TEMP_EXE, PROGRAMDATA_EXE)
)


def scan(**sections: object) -> ScanResult:
    snap = Snapshot(elevated=True, system=SYSTEM, defender=(WHOLE_DRIVE,), **sections)  # type: ignore[arg-type]
    return run_scan(FakeInspector(snap))


def drive_findings(result: ScanResult) -> list[tuple[str, Level]]:
    check = next(c for c in result.checks if c.check == "defender")
    return sorted((f.item, f.level) for f in check.findings if f.item in ("C:\\", "D:\\"))


def test_alone_it_stays_conferir_with_its_own_text() -> None:
    result = scan()
    assert drive_findings(result) == [("C:\\", Level.CONFERIR), ("D:\\", Level.CONFERIR)]
    check = next(c for c in result.checks if c.check == "defender")
    texts = {s.text for f in check.findings for s in f.signals}
    assert "O Defender foi instruído a não analisar uma unidade inteira." in texts
    assert overall_level(result.checks) is Level.CONFERIR


def run_key(command: str) -> AutorunEntry:
    return AutorunEntry(r"HKCU\...\Run", "x", command, "PC\\Ana", "run")


WITH_OTHER_SIGNS: dict[str, Callable[[], dict[str, object]]] = {
    "run key to AppData": lambda: {"autoruns": (run_key(f'"{DROP}"'),), "signatures": UNSIGNED},
    "run key to Temp": lambda: {"autoruns": (run_key(f'"{TEMP_EXE}"'),), "signatures": UNSIGNED},
    "scheduled task to AppData": lambda: {
        "tasks": (TaskInfo("\\", "T", True, (TaskAction(DROP, ""),), ("TimeTrigger",), None),),
        "signatures": UNSIGNED,
    },
    "mining port connection": lambda: {
        "processes": (ProcessInfo(7, "a.exe", DROP, "a.exe", "PC\\Ana", None, None),),
        "connections": (ConnectionInfo(7, "93.184.216.34", 3333, "ESTABLISHED"),),
        "signatures": UNSIGNED,
    },
    "mining command line": lambda: {
        "processes": (
            ProcessInfo(
                7,
                "tool.exe",
                r"C:\Tools\tool.exe",
                "tool.exe --donate-level=1",
                "PC\\Ana",
                None,
                None,
            ),
        ),
    },
    "miner process name": lambda: {
        "processes": (
            ProcessInfo(7, "xmrig.exe", r"C:\Tools\xmrig.exe", "xmrig.exe", "PC\\Ana", None, None),
        ),
    },
}


@pytest.mark.parametrize("name", sorted(WITH_OTHER_SIGNS))
def test_combined_with_another_sign_the_exclusion_raises_the_set_to_suspeito(name: str) -> None:
    result = scan(**WITH_OTHER_SIGNS[name]())
    assert drive_findings(result) == [("C:\\", Level.SUSPEITO), ("D:\\", Level.SUSPEITO)]
    assert overall_level(result.checks) is Level.SUSPEITO
    check = next(c for c in result.checks if c.check == "defender")
    finding = next(f for f in check.findings if f.item == "C:\\")
    assert "defender_whole_drive_exclusion_with_evidence" in {s.code for s in finding.signals}
    assert any(e.startswith("junto com:") for e in finding.evidence)


def test_a_known_signed_program_in_appdata_does_not_count_as_a_sign() -> None:
    path = r"C:\Users\Ana\AppData\Local\Discord\Update.exe"
    sig = Signature(path, SignatureStatus.VALID, SignerKind.OTHER, "O=Discord Inc.")
    result = scan(autoruns=(run_key(f'"{path}" --processStart'),), signatures=(sig,))
    assert drive_findings(result) == [("C:\\", Level.CONFERIR), ("D:\\", Level.CONFERIR)]


def test_persistence_in_programdata_alone_does_not_escalate_the_runner_case() -> None:
    result = scan(
        tasks=(TaskInfo("\\", "agent", True, (TaskAction(PROGRAMDATA_EXE, ""),), (), None),),
        signatures=UNSIGNED,
    )
    assert drive_findings(result) == [("C:\\", Level.CONFERIR), ("D:\\", Level.CONFERIR)]


def test_another_exclusion_kind_is_not_a_whole_drive_and_does_not_escalate() -> None:
    narrow = DefenderState(True, True, False, 1, (), (r"C:\Games",), (), (), ())
    snap = Snapshot(
        elevated=True,
        system=SYSTEM,
        defender=(narrow,),
        autoruns=(run_key(f'"{DROP}"'),),
        signatures=UNSIGNED,
    )
    result = run_scan(FakeInspector(snap))
    check = next(c for c in result.checks if c.check == "defender")
    assert all(
        "defender_whole_drive_exclusion_with_evidence" not in {s.code for s in f.signals}
        for f in check.findings
    )


# Unclassified threats -------------------------------------------------------------------


def suspicious_without_a_type() -> ScanResult:
    """A system name running from AppData: SUSPEITO, but not a miner and not a backdoor."""
    path = r"C:\Users\Ana\AppData\Roaming\svchost.exe"
    snap = Snapshot(
        elevated=True,
        system=SYSTEM,
        processes=(ProcessInfo(9, "svchost.exe", path, path, "PC\\Ana", None, 1.0),),
    )
    return run_scan(FakeInspector(snap))


def test_a_suspect_without_miner_or_backdoor_signs_is_an_unclassified_threat() -> None:
    result = suspicious_without_a_type()
    assert overall_level(result.checks) is Level.SUSPEITO
    threats = diagnose(result.checks, result.snapshot).threats
    assert [t.kind for t in threats] == [UNCLASSIFIED_KIND]
    assert threats[0].name == "Ameaça não classificada"
    assert "não distingue" in threats[0].note.lower()
    assert "ladrões de palavras-passe" in threats[0].note
    assert "publicidade" in threats[0].note


def test_the_text_and_the_json_say_this_version_does_not_tell_the_types_apart() -> None:
    result = suspicious_without_a_type()
    report = build_report(result)
    text = render_text(report)
    assert "Ameaça não classificada" in text
    assert "não distingue" in text.lower()
    assert "Ameaça provável" not in text
    assert report["diagnosis"]["threats"][0]["kind"] == UNCLASSIFIED_KIND


def test_it_is_never_forced_into_miner_or_backdoor() -> None:
    names = {t.kind for t in diagnose(suspicious_without_a_type().checks).threats}
    assert names.isdisjoint({"minerador", "trojan"})


def test_a_suspect_fully_explained_by_a_named_type_does_not_also_produce_an_unclassified_one() -> (
    None
):
    snap = Snapshot(
        elevated=True,
        system=SYSTEM,
        hosts=("0.0.0.0 update.microsoft.com", "0.0.0.0 www.virustotal.com"),
    )
    result = run_scan(FakeInspector(snap))
    kinds = {t.kind for t in diagnose(result.checks, result.snapshot).threats}
    assert kinds == {"trojan"}


def test_a_lone_whole_drive_case_with_no_suspect_has_no_threat_at_all() -> None:
    assert diagnose(scan().checks).threats == ()


def test_a_suspect_left_over_next_to_a_classified_one_is_still_reported_apart() -> None:
    base = load_fixture("miner_pc")
    path = r"C:\Users\Ana\AppData\Roaming\svchost.exe"
    extra = ProcessInfo(99, "svchost.exe", path, path, "PC\\Ana", None, 0.0)
    snap = Snapshot(
        elevated=True,
        system=base.system,
        processes=(*base.processes, extra),
        autoruns=base.autoruns,
        signatures=base.signatures,
        defender=base.defender,
        hosts=base.hosts,
        wmi_bindings=base.wmi_bindings,
        files=base.files,
        connections=base.connections,
        tasks=base.tasks,
        hashes=base.hashes,
    )
    result = run_scan(FakeInspector(snap))
    kinds = {t.kind for t in diagnose(result.checks, result.snapshot).threats}
    assert {"minerador", UNCLASSIFIED_KIND} <= kinds
