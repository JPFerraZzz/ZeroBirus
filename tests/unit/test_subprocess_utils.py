import sys

import pytest

from zerobirus.platform.subprocess_utils import Completed, OutputTooLarge, TimedOut, run_limited


def run(
    code: str,
    *,
    timeout: float = 10.0,
    max_stdout: int = 1000,
    max_stderr: int = 1000,
) -> Completed:
    return run_limited(
        [sys.executable, "-c", code],
        stdin=b"",
        timeout=timeout,
        max_stdout=max_stdout,
        max_stderr=max_stderr,
    )


def test_small_output_and_stdin_round_trip() -> None:
    done = run_limited(
        [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read().upper())"],
        stdin=b"abc",
        timeout=10,
        max_stdout=100,
        max_stderr=100,
    )
    assert (done.returncode, done.stdout) == (0, b"ABC")


def test_a_child_that_writes_too_much_is_killed() -> None:
    with pytest.raises(OutputTooLarge):
        run("import sys\nwhile True: sys.stdout.write('x' * 10000); sys.stdout.flush()")


def test_a_child_that_runs_too_long_is_killed() -> None:
    with pytest.raises(TimedOut):
        run("import time; time.sleep(30)", timeout=0.3)


def test_stderr_is_cut_not_an_error() -> None:
    done = run("import sys; sys.stderr.write('e' * 5000)", max_stderr=100)
    assert done.returncode == 0
    assert done.stderr_truncated
    assert len(done.stderr) <= 100


def test_the_exit_code_is_reported() -> None:
    assert run("raise SystemExit(3)").returncode == 3


def test_the_environment_given_is_the_only_one() -> None:
    import os

    done = run_limited(
        [sys.executable, "-c", "import os; print(sorted(k for k in os.environ if k == 'ZB_X'))"],
        stdin=b"",
        timeout=10,
        max_stdout=1000,
        max_stderr=1000,
        env={"ZB_X": "1", "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")},
    )
    assert b"ZB_X" in done.stdout
