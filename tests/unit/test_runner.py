import threading
import time

import pytest

from zerobirus.core.models import CheckResult, Level
from zerobirus.platform.base import Inspector
from zerobirus.platform.fake import FakeInspector
from zerobirus.scanners import Scanner
from zerobirus.scanners.runner import ScanCancelled, run_scan


def ok(inspector: Inspector) -> CheckResult:
    return CheckResult(check="ok")


def boom(inspector: Inspector) -> CheckResult:
    raise PermissionError("acesso negado")


def test_a_failing_check_becomes_nao_verificado_and_does_not_stop_the_others() -> None:
    result = run_scan(FakeInspector("clean_pc"), scanners={"ok": ok, "boom": boom})
    by = {c.check: c for c in result.checks}
    assert by["ok"].level is Level.OK
    assert by["boom"].level is Level.NAO_VERIFICADO
    assert "PermissionError" in by["boom"].reason


def test_a_check_that_hangs_is_abandoned_with_a_reason() -> None:
    release = threading.Event()

    def hang(inspector: Inspector) -> CheckResult:
        release.wait(5)
        return CheckResult(check="hang")

    started = time.monotonic()
    result = run_scan(FakeInspector("clean_pc"), timeout=0.2, scanners={"hang": hang, "ok": ok})
    release.set()
    assert time.monotonic() - started < 3
    by = {c.check: c for c in result.checks}
    assert by["hang"].level is Level.NAO_VERIFICADO
    assert "tempo limite" in by["hang"].reason
    assert by["ok"].level is Level.OK


def named(name: str) -> Scanner:
    def scanner(inspector: Inspector) -> CheckResult:
        return CheckResult(check=name)

    return scanner


def test_checks_keep_their_declared_order() -> None:
    scanners = {n: named(n) for n in ("b", "a", "c")}
    result = run_scan(FakeInspector("clean_pc"), scanners=scanners)
    assert [c.check for c in result.checks] == ["b", "a", "c"]


def test_the_backend_is_asked_once_per_question_even_with_parallel_checks() -> None:
    calls: list[str] = []

    class Counting(FakeInspector):
        def processes(self):  # type: ignore[no-untyped-def]
            calls.append("processes")
            time.sleep(0.05)
            return super().processes()

    def ask(inspector: Inspector) -> CheckResult:
        inspector.processes()
        return CheckResult(check="x")

    run_scan(Counting("clean_pc"), scanners={f"c{i}": ask for i in range(6)})
    assert calls == ["processes"]


def test_progress_is_reported_per_check_and_cancelling_raises() -> None:
    done: list[str] = []
    run_scan(
        FakeInspector("clean_pc"),
        scanners={"a": named("a"), "b": named("b")},
        on_check_done=lambda name, _result: done.append(name),
    )
    assert sorted(done) == ["a", "b"]

    release = threading.Event()

    def slow(inspector: Inspector) -> CheckResult:
        release.wait(5)
        return CheckResult(check="slow")

    cancel = threading.Event()
    timer = threading.Timer(0.2, cancel.set)
    timer.start()
    try:
        with pytest.raises(ScanCancelled):
            run_scan(FakeInspector("clean_pc"), scanners={"slow": slow}, cancel=cancel)
    finally:
        release.set()
        timer.cancel()


def test_concurrent_requests_for_the_same_signature_wait_for_the_one_fetch() -> None:
    """A second check asking for a path that is being fetched must get the answer, not nothing."""
    from zerobirus.core.models import Observed, Signature, SignatureStatus
    from zerobirus.platform.recording import RecordingInspector

    calls: list[list[str]] = []
    path = r"C:\x\a.exe"

    class Slow(FakeInspector):
        def signatures(self, paths):  # type: ignore[no-untyped-def]
            calls.append(list(paths))
            time.sleep(0.3)
            return Observed((Signature(path, SignatureStatus.UNSIGNED),))

    rec = RecordingInspector(Slow("clean_pc"))
    results: list[Observed[Signature]] = []
    threads = [
        threading.Thread(target=lambda: results.append(rec.signatures([path]))) for _ in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1
    assert all(len(r.items) == 1 and r.items[0].status is SignatureStatus.UNSIGNED for r in results)
