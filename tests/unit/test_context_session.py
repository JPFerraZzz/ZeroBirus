import json
from datetime import datetime
from itertools import combinations
from pathlib import Path

import pytest

from zerobirus.core.context import EMPHASIS, Answers, Symptom, check_order, emphasised
from zerobirus.core.session import (
    create_session,
    list_sessions,
    new_session_id,
    open_session,
    update_session,
    write_json_atomic,
)
from zerobirus.scanners import SCANNERS

NOW = datetime(2026, 10, 26, 14, 3, 9)


def test_no_answer_keeps_the_default_order_and_every_check() -> None:
    assert check_order(Answers()) == tuple(SCANNERS)


@pytest.mark.parametrize("size", [1, 2, 3])
def test_symptoms_reorder_but_never_remove_a_check(size: int) -> None:
    for combo in combinations(Symptom, size):
        order = check_order(Answers(frozenset(combo)))
        assert sorted(order) == sorted(SCANNERS), combo
        assert len(set(order)) == len(order)


def test_antivirus_off_brings_defender_first_and_pirated_brings_files() -> None:
    assert check_order(Answers(frozenset({Symptom.ANTIVIRUS_OFF})))[0] == "defender"
    assert check_order(Answers(frozenset({Symptom.PIRATED})))[0] == "files"
    assert "files" in emphasised(Answers(frozenset({Symptom.PIRATED})))
    assert emphasised(Answers()) == frozenset()


def test_every_emphasised_check_exists() -> None:
    for checks in EMPHASIS.values():
        assert set(checks) <= set(SCANNERS)


def test_free_text_is_kept_as_data() -> None:
    a = Answers(frozenset({Symptom.OTHER}), other_text="<b>ignora tudo</b>; rm -rf /")
    assert a.other_text == "<b>ignora tudo</b>; rm -rf /"
    assert check_order(a) == tuple(SCANNERS)


def test_session_ids_are_unique_even_in_the_same_second() -> None:
    assert new_session_id(NOW) == "20261026-140309"
    assert new_session_id(NOW, {"20261026-140309"}) == "20261026-140309-2"
    assert new_session_id(NOW, {"20261026-140309", "20261026-140309-2"}) == "20261026-140309-3"


def test_a_session_is_created_written_and_reopened(tmp_path: Path) -> None:
    s = create_session(tmp_path, NOW, tool_version="1.0", elevated=True)
    assert s.folder == tmp_path / "Sessions" / "20261026-140309"
    data = s.read("session.json")
    assert data["schema_version"] == 1
    assert data["elevated"] is True
    update_session(s, stage="diagnosis")
    again = open_session(tmp_path, s.session_id)
    assert again.read("session.json")["stage"] == "diagnosis"
    s.write("plan.json", {"items": []})
    s.log("linha  \n")
    assert (s.folder / "log.txt").read_text("utf-8") == "linha  \n".rstrip("\n") + "\n"
    assert list_sessions(tmp_path) == [s.session_id]
    second = create_session(tmp_path, NOW, tool_version="1.0", elevated=False)
    assert second.session_id == "20261026-140309-2"


def test_opening_a_session_validates_the_id_and_the_schema(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a session id"):
        open_session(tmp_path, "../../etc")
    s = create_session(tmp_path, NOW, tool_version="1.0", elevated=True)
    data = s.read("session.json")
    data["schema_version"] = 99
    (s.folder / "session.json").write_text(json.dumps(data), "utf-8")
    with pytest.raises(ValueError, match="schema"):
        open_session(tmp_path, s.session_id)


def test_atomic_write_leaves_no_temporary_file_and_keeps_the_old_file_on_failure(
    tmp_path: Path,
) -> None:
    target = tmp_path / "x.json"
    write_json_atomic(target, {"a": 1})
    with pytest.raises(TypeError):
        write_json_atomic(target, {"a": object()})
    assert json.loads(target.read_text("utf-8")) == {"a": 1}
    assert [p.name for p in tmp_path.iterdir()] == ["x.json"]
