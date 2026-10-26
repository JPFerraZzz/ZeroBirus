"""Parsers for what the Windows backend collects. Samples follow the shape the PowerShell
scripts emit; the real shape is confirmed on windows-latest (tests/unit/test_windows_backend.py).
"""

import pytest

from zerobirus.core.models import SignatureStatus
from zerobirus.core.parsing import (
    classify_signer,
    expand_vars,
    iso_minutes,
    organisation,
    parse_defender,
    parse_shortcuts,
    parse_signatures,
    parse_tasks,
    parse_wmi,
    profile_variables,
)
from zerobirus.core.safety import SignerKind

MS = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"


def test_organisation_handles_quotes_commas_and_missing() -> None:
    assert organisation(MS) == "Microsoft Corporation"
    assert organisation('CN=X, O="Acme, Inc.", C=US') == "Acme, Inc."
    assert organisation("CN=NoOrg") == ""
    assert organisation("") == ""


@pytest.mark.parametrize(
    ("subject", "kind"),
    [
        (MS, SignerKind.MICROSOFT),
        ("CN=Microsoft Corporation, O=Microsoft Corporation, C=US", SignerKind.MICROSOFT),
        ("CN=Kaspersky Lab, O=AO Kaspersky Lab, C=RU", SignerKind.ANTIVIRUS_VENDOR),
        ("CN=ESET, spol. s r.o., O=ESET, spol. s r.o.", SignerKind.ANTIVIRUS_VENDOR),
        ("CN=Discord Inc., O=Discord Inc.", SignerKind.OTHER),
        # a lookalike must not be trusted as Microsoft
        ("CN=Microsoft Corporation, O=Microsoft Corporation Fake Ltd", SignerKind.OTHER),
        ("CN=Microsoft Corporation", SignerKind.OTHER),
        ("", SignerKind.OTHER),
    ],
)
def test_classify_signer(subject: str, kind: SignerKind) -> None:
    assert classify_signer(subject) is kind


def test_parse_signatures_maps_statuses_and_skips_garbage() -> None:
    raw = [
        {"path": r"C:\a.exe", "status": 0, "subject": MS},
        {"path": r"C:\b.exe", "status": 2, "subject": ""},
        {"path": r"C:\c.exe", "status": 3, "subject": "O=X"},
        {"path": r"C:\d.exe", "status": 4, "subject": "O=X"},
        {"path": r"C:\e.lnk", "status": 5, "subject": ""},
        {"path": r"C:\f.exe", "status": -1, "subject": ""},
        {"path": "", "status": 0},
        {"path": r"C:\g.exe", "status": True},
        {"path": r"C:\h.exe"},
        "garbage",
    ]
    got = {s.path: (s.status, s.kind) for s in parse_signatures(raw)}
    assert got == {
        r"C:\a.exe": (SignatureStatus.VALID, SignerKind.MICROSOFT),
        r"C:\b.exe": (SignatureStatus.UNSIGNED, SignerKind.UNSIGNED),
        r"C:\c.exe": (SignatureStatus.INVALID, SignerKind.OTHER),
        r"C:\d.exe": (SignatureStatus.INVALID, SignerKind.OTHER),
        r"C:\e.lnk": (SignatureStatus.UNKNOWN, SignerKind.OTHER),
        r"C:\f.exe": (SignatureStatus.UNKNOWN, SignerKind.OTHER),
    }


def test_a_single_powershell_object_is_accepted_as_a_list() -> None:
    assert len(parse_signatures({"path": r"C:\a.exe", "status": 0, "subject": MS})) == 1


@pytest.mark.parametrize(
    ("text", "minutes"),
    [
        ("PT5M", 5),
        ("PT1H", 60),
        ("PT1H30M", 90),
        ("P1D", 1440),
        ("PT30S", 1),
        ("PT0S", None),
        ("", None),
        (None, None),
        ("junk", None),
        ("P", None),
    ],
)
def test_iso_minutes(text: str | None, minutes: int | None) -> None:
    assert iso_minutes(text) == minutes


def test_parse_tasks() -> None:
    raw = [
        {
            "folder": "\\Microsoft\\Windows\\X\\",
            "name": "T",
            "state": 3,
            "actions": [
                {"execute": r"C:\a.exe", "arguments": "-x"},
                {"execute": "", "arguments": ""},
            ],
            "triggers": ["MSFT_TaskTimeTrigger"],
            "repetition": "PT1M",
        },
        {
            "folder": "\\",
            "name": "Off",
            "state": 1,
            "actions": {"execute": "b.exe"},
            "triggers": None,
        },
    ]
    result = parse_tasks(raw, elevated=True)
    assert result.gaps == ()
    first, second = result.items
    assert first.actions[0].execute == r"C:\a.exe"
    assert len(first.actions) == 1
    assert first.repeat_minutes == 1
    assert first.enabled
    assert not second.enabled
    assert second.actions[0].execute == "b.exe"


def test_tasks_without_administrator_are_incomplete() -> None:
    assert parse_tasks([], elevated=False).gaps


def test_parse_defender_reads_values_and_marks_unreadable_ones() -> None:
    raw = {
        "realtime": True,
        "tamper": False,
        "amrunning": "Normal",
        "sigage": 2,
        "threats": ["Trojan:Win32/X"],
        "excl_paths": [r"C:\x"],
        "excl_ext": [],
        "excl_proc": None,
        "excl_ip": ["N/A: Must be an administrator to view exclusions"],
        "errors": [],
    }
    state = parse_defender(raw, elevated=True).items[0]
    assert state.realtime is True
    assert state.tamper_protection is False
    assert state.passive_mode is False
    assert state.signature_age_days == 2
    assert state.threats == ("Trojan:Win32/X",)
    assert state.exclusion_paths == (r"C:\x",)
    assert state.exclusion_extensions == ()
    assert state.exclusion_processes is None
    assert state.exclusion_ips is None


def test_defender_exclusions_are_never_readable_without_administrator() -> None:
    raw: dict[str, object] = {
        "realtime": True,
        "tamper": True,
        "amrunning": "Normal",
        "sigage": 1,
        "threats": [],
        "excl_paths": [],
        "excl_ext": [],
        "excl_proc": [],
        "excl_ip": [],
        "errors": [],
    }
    state = parse_defender(raw, elevated=False).items[0]
    assert state.exclusion_paths is None
    assert state.threats is None
    assert state.realtime is True


def test_defender_passive_mode_and_unavailable() -> None:
    passive = parse_defender({"amrunning": "Passive Mode", "errors": []}, elevated=True).items[0]
    assert passive.passive_mode is True
    assert passive.realtime is None
    down = parse_defender({"errors": ["status", "preference"]}, elevated=True)
    assert down.items == ()
    assert down.gaps
    assert parse_defender([], elevated=True).gaps


def test_parse_wmi_and_shortcuts() -> None:
    wmi = parse_wmi(
        [
            {
                "filter": "F",
                "consumer": "C",
                "consumer_class": "CommandLineEventConsumer",
                "command": "x.exe",
            }
        ]
    )
    assert (wmi[0].filter_name, wmi[0].consumer_class, wmi[0].command) == (
        "F",
        "CommandLineEventConsumer",
        "x.exe",
    )
    assert parse_wmi(None) == ()
    sc = parse_shortcuts(
        [
            {"path": r"C:\s.lnk", "target": r"C:\a b\x.exe", "arguments": "-q"},
            {"path": "t", "target": ""},
        ]
    )
    assert sc == {r"C:\s.lnk": r'"C:\a b\x.exe" -q'}


def test_expand_vars_uses_the_given_profile_and_leaves_unknown_names() -> None:
    env = profile_variables(r"C:\Users\Bob")
    assert expand_vars(r"%APPDATA%\x\a.exe", env) == r"C:\Users\Bob\AppData\Roaming\x\a.exe"
    assert expand_vars(r"%appdata%\a", env) == r"C:\Users\Bob\AppData\Roaming\a"
    assert expand_vars(r"%NOPE%\a", env) == r"%NOPE%\a"
    assert expand_vars(r"%TEMP%\a", env) == r"C:\Users\Bob\AppData\Local\Temp\a"


def test_empty_strings_from_powershell_are_not_exclusions() -> None:
    """On a real runner PowerShell gave [''] for properties that had no values."""
    raw: dict[str, object] = {
        "realtime": True,
        "tamper": True,
        "amrunning": "Normal",
        "sigage": 1,
        "threats": [],
        "excl_paths": ["C:\\", "D:\\"],
        "excl_ext": [""],
        "excl_proc": [""],
        "excl_ip": [""],
        "errors": [],
    }
    state = parse_defender(raw, elevated=True).items[0]
    assert state.exclusion_paths == ("C:\\", "D:\\")
    assert state.exclusion_extensions == ()
    assert state.exclusion_processes == ()
    assert state.exclusion_ips == ()
