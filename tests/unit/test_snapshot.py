import json

import pytest

from zerobirus.core.models import (
    CheckResult,
    DefenderState,
    Finding,
    Level,
    ProcessInfo,
    Signature,
    SignatureStatus,
)
from zerobirus.core.safety import SignerKind
from zerobirus.core.snapshot import (
    Snapshot,
    from_jsonable,
    snapshot_from_dict,
    snapshot_to_dict,
    to_jsonable,
)
from zerobirus.platform.fake import FakeInspector, fixture_names, load_fixture


@pytest.mark.parametrize("name", fixture_names())
def test_every_fixture_round_trips_through_json(name: str) -> None:
    snap = load_fixture(name)
    again = snapshot_from_dict(json.loads(json.dumps(snapshot_to_dict(snap))))
    assert again == snap


def test_enums_and_none_round_trip() -> None:
    snap = load_fixture("clean_pc")
    sig = Signature(r"C:\a.exe", SignatureStatus.INVALID, SignerKind.UNSIGNED, "")
    snap2 = Snapshot(
        elevated=False,
        system=snap.system,
        processes=(ProcessInfo(1, "a", None, "", "u", None, 12.5),),
        signatures=(sig,),
        defender=(DefenderState(realtime=None, exclusion_paths=("C:\\x",)),),
        gaps={"wmi_bindings": ("sem administrador",)},
    )
    assert snapshot_from_dict(json.loads(json.dumps(snapshot_to_dict(snap2)))) == snap2


def test_decoder_rejects_wrong_types_and_unknown_fields() -> None:
    with pytest.raises(TypeError):
        from_jsonable(
            ProcessInfo,
            {"pid": "4", "name": "a", "path": None, "cmdline": "", "user": "", "parent_pid": None},
        )
    with pytest.raises(TypeError, match="unknown fields"):
        from_jsonable(Signature, {"path": "a", "status": "valid", "extra": 1})
    with pytest.raises(ValueError, match="schema"):
        snapshot_from_dict({"schema_version": 99})


def test_bool_is_not_accepted_as_int() -> None:
    with pytest.raises(TypeError):
        from_jsonable(
            ProcessInfo,
            {"pid": True, "name": "a", "path": None, "cmdline": "", "user": "", "parent_pid": None},
        )


def test_to_jsonable_sorts_sets_and_uses_enum_values() -> None:
    assert to_jsonable(frozenset({3, 1, 2})) == [1, 2, 3]
    assert to_jsonable(Level.OK) == "OK"


def test_fake_inspector_reports_gaps_from_the_snapshot() -> None:
    snap = load_fixture("clean_pc")
    inspector = FakeInspector(
        Snapshot(elevated=False, system=snap.system, gaps={"wmi_bindings": ("sem administrador",)})
    )
    assert inspector.wmi_bindings().gaps == ("sem administrador",)
    assert inspector.autoruns().gaps == ()


def test_partial_check_is_never_ok() -> None:
    partial = CheckResult(check="run", verified=False, reason="perfil nao carregado")
    assert partial.level is Level.NAO_VERIFICADO
    f = Finding(id="f", item="x", location="y", level=Level.SUSPEITO, description="d")
    assert (
        CheckResult(check="run", findings=(f,), verified=False, reason="r").level is Level.SUSPEITO
    )
    ok = Finding(id="f", item="x", location="y", level=Level.OK, description="d")
    assert (
        CheckResult(check="run", findings=(ok,), verified=False, reason="r").level
        is Level.NAO_VERIFICADO
    )
