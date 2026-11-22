"""BigDiag (report rules) and AllUp (parsing, plan, independent verification)."""

import copy
from typing import Any

import pytest

from zerobirus.core.allup import (
    PACKAGE_ID,
    UpdatePlan,
    Upgrade,
    authorize_updates,
    parse_upgrades,
)
from zerobirus.core.bigdiag import DiagReport, Section, Status, build_report, render_text
from zerobirus.core.models import DefenderState
from zerobirus.core.ram import MEGA, MemorySnapshot
from zerobirus.platform.fake.diag import demo_reading
from zerobirus.platform.fake.winget import FakePackageUpdater
from zerobirus.remediation.updates import NotAuthorized, run_updates

TWO = ["Demo.Browser", "Demo.Player"]
MEMORY = MemorySnapshot(16 * 1024 * MEGA, 8 * 1024 * MEGA, ())
DEFENDER = DefenderState(realtime=True, signature_age_days=1, threats=())


def report(raw: dict[str, Any], **kw: Any) -> DiagReport:
    return build_report(
        raw,
        memory=kw.get("memory", MEMORY),
        defender=kw.get("defender", DEFENDER),
        generated_at="2026-10-29 12:00",
    )


def section(rep: DiagReport, title: str) -> Section:
    return next(s for s in rep.sections if s.title.startswith(title))


# BigDiag ---------------------------------------------------------------------------------


def test_the_demo_reading_gives_a_report_whose_worst_part_is_the_full_c_drive() -> None:
    rep = report(demo_reading())
    assert [s.title for s in rep.sections][:3] == ["Sistema", "Processador", "Memória RAM"]
    disks = section(rep, "Discos")
    assert disks.status is Status.ATENCAO  # the HDD says Warning and has read errors
    assert section(rep, "Espaço").status is Status.PROBLEMA  # C: has under 10% free
    assert rep.status is Status.PROBLEMA


def test_what_could_not_be_read_is_never_reported_as_good() -> None:
    rep = report({}, memory=None, defender=None)
    assert all(s.status is Status.NAO_LIDO for s in rep.sections)
    assert rep.status is Status.NAO_LIDO


def test_one_part_failing_does_not_hide_the_others() -> None:
    raw = demo_reading()
    del raw["disks"]
    rep = report(raw)
    assert section(rep, "Discos").status is Status.NAO_LIDO
    assert section(rep, "Placa").status is Status.OK


@pytest.mark.parametrize(
    ("health", "expected"),
    [("Healthy", Status.OK), ("Warning", Status.ATENCAO), ("Unhealthy", Status.PROBLEMA)],
)
def test_disk_health_maps_to_status(health: str, expected: Status) -> None:
    raw = {"disks": [{"name": "d", "media": "SSD", "size": 10**12, "health": health}]}
    assert section(report(raw), "Discos").status is expected


def test_wear_and_temperature_thresholds() -> None:
    def status(**smart: float) -> Status:
        d = {"name": "d", "media": "SSD", "size": 10**12, "health": "Healthy", **smart}
        return Status(section(report({"disks": [d]}), "Discos").status)

    assert status(wear_percent=10) is Status.OK
    assert status(wear_percent=75) is Status.ATENCAO
    assert status(wear_percent=95) is Status.PROBLEMA
    assert status(temperature_c=60) is Status.ATENCAO
    assert status(read_errors=3) is Status.ATENCAO


def test_a_powershell_single_item_comes_as_an_object_not_a_list() -> None:
    raw = demo_reading()
    raw["gpus"] = raw["gpus"][0]
    assert section(report(raw), "Placa").status is Status.OK


def test_mrt_threats_are_a_problem_and_a_missing_log_is_unread() -> None:
    raw = demo_reading()
    raw["mrt"] = {"version": "5.1", "last_run": "2026-10-01", "outcome": "threats"}
    assert section(report(raw), "Ferramenta").status is Status.PROBLEMA
    raw["mrt"] = {"version": "5.1", "last_run": None, "outcome": None}
    assert section(report(raw), "Ferramenta").status is Status.NAO_LIDO


def test_defender_off_and_old_signatures() -> None:
    off = DefenderState(realtime=False, signature_age_days=20)
    sec = section(report(demo_reading(), defender=off), "Microsoft Defender")
    assert sec.status is Status.PROBLEMA
    assert any(line.status is Status.ATENCAO for line in sec.lines)


def test_failures_thresholds() -> None:
    raw = copy.deepcopy(demo_reading())
    raw["failures"]["bugchecks"] = 5
    assert section(report(raw), "Falhas").status is Status.PROBLEMA


def test_the_exported_text_is_redacted_and_says_nothing_was_changed() -> None:
    raw = demo_reading()
    raw["gpus"][0]["name"] = "Placa C:\\Users\\Ana\\segredo --password=hunter2"
    text = render_text(report(raw), version="9.9.9")
    assert "hunter2" not in text
    assert "só de leitura" in text
    assert "9.9.9" in text


# AllUp -----------------------------------------------------------------------------------

EN = """\
\\
   -
Name                     Id                  Version   Available  Source
----------------------------------------------------------------------------
Mozilla Firefox (x64 en) Mozilla.Firefox     130.0     131.0      winget
7-Zip                    7zip.7zip           23.01     24.08      winget
Microsoft Visual C++ 2015-2022 Redistributable (x64) Microsoft.VCRedist.2015+.x64 14.38 14.40 winget
Program Without Source   Vendor.Thing        < 1.0     1.2
3 upgrades available.
"""
PT = """\
Nome                Id            Versão   Disponível  Origem
-----------------------------------------------------------
Leitor de PDF       Vendor.Pdf    1.0      1.1         winget
2 atualizações disponíveis.
"""


def test_parse_upgrades_english_and_portuguese_and_odd_rows() -> None:
    rows = parse_upgrades(EN)
    assert [u.id for u in rows] == [
        "Mozilla.Firefox",
        "7zip.7zip",
        "Microsoft.VCRedist.2015+.x64",
        "Vendor.Thing",
    ]
    assert rows[0] == Upgrade(
        "Mozilla Firefox (x64 en)", "Mozilla.Firefox", "130.0", "131.0", "winget"
    )
    assert rows[3].version == "<1.0"
    assert rows[3].source == ""
    assert [u.id for u in parse_upgrades(PT)] == ["Vendor.Pdf"]


def test_parse_ignores_anything_that_is_not_a_table() -> None:
    assert parse_upgrades("") == ()
    assert parse_upgrades("No installed package found matching input criteria.") == ()
    hostile = "N\n-----\nname --force x y\nname $(calc) 1 2 winget\nname id;rm 1 2 winget\n"
    assert parse_upgrades(hostile) == ()


@pytest.mark.parametrize("bad", ["--force", "-x", "a b", "a;b", "a$(b)", "", "../x", "a" * 200])
def test_package_ids_that_could_be_options_or_commands_are_not_ids(bad: str) -> None:
    assert not PACKAGE_ID.match(bad)


def listed() -> tuple[Upgrade, ...]:
    return FakePackageUpdater().list_upgrades()


def test_the_plan_only_takes_listed_ids() -> None:
    with pytest.raises(ValueError, match="not in the list"):
        authorize_updates(listed(), ["Evil.Thing"], session_id="s", authorised_at="t")
    with pytest.raises(ValueError, match="nothing"):
        authorize_updates(listed(), [], session_id="s", authorised_at="t")


def test_updates_are_confirmed_by_a_fresh_listing() -> None:
    fake = FakePackageUpdater()
    plan = authorize_updates(
        listed(), ["Demo.Browser", "Demo.Player"], session_id="s", authorised_at="t"
    )
    results = run_updates(plan, listed(), fake)
    assert [r.confirmed for r in results] == [True, True]
    assert fake.installed == ["Demo.Browser", "Demo.Player"]
    assert [u.id for u in fake.list_upgrades()] == ["Demo.Editor"]


def test_a_success_that_does_not_stick_is_not_claimed() -> None:
    fake = FakePackageUpdater()
    fake.fail.add("Demo.Browser")
    plan = authorize_updates(listed(), ["Demo.Browser"], session_id="s", authorised_at="t")
    [r] = run_updates(plan, listed(), fake)
    assert not r.confirmed
    assert "continua a aparecer" in r.detail


def test_a_failing_package_does_not_stop_the_next_one() -> None:
    fake = FakePackageUpdater()
    fake.error.add("Demo.Browser")
    plan = authorize_updates(
        listed(), ["Demo.Browser", "Demo.Player"], session_id="s", authorised_at="t"
    )
    results = run_updates(plan, listed(), fake)
    assert [r.confirmed for r in results] == [False, True]


def test_stopping_skips_the_rest_without_installing() -> None:
    fake = FakePackageUpdater()
    plan = authorize_updates(
        listed(), ["Demo.Browser", "Demo.Player"], session_id="s", authorised_at="t"
    )
    calls = iter([False, True])
    results = run_updates(plan, listed(), fake, should_stop=lambda: next(calls))
    assert fake.installed == ["Demo.Browser"]
    assert "pararam" in results[1].detail


def test_a_plan_altered_after_authorising_is_refused_and_nothing_runs() -> None:
    fake = FakePackageUpdater()
    plan = authorize_updates(listed(), ["Demo.Browser"], session_id="s", authorised_at="t")
    forged = UpdatePlan(
        plan.session_id, plan.authorised_at, ("Demo.Browser", "Demo.Editor"), plan.digest
    )
    with pytest.raises(NotAuthorized):
        run_updates(forged, listed(), fake)
    assert fake.installed == []
