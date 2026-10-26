"""Run a child process with hard limits on time and output size. No shell, ever."""

from __future__ import annotations

import contextlib
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import IO


class OutputTooLarge(RuntimeError):
    """The child wrote more than the allowed output and was killed."""


class TimedOut(RuntimeError):
    """The child ran out of time and was killed."""


@dataclass(frozen=True, slots=True)
class Completed:
    returncode: int
    stdout: bytes
    stderr: bytes
    stderr_truncated: bool


def _read(stream: IO[bytes], limit: int, sink: list[bytes], over: threading.Event) -> None:
    total = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            return
        total += len(chunk)
        if total > limit:
            over.set()
            return
        sink.append(chunk)


def run_limited(
    args: Sequence[str],
    *,
    stdin: bytes,
    timeout: float,
    max_stdout: int,
    max_stderr: int,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    creationflags: int = 0,
) -> Completed:
    """Run ``args`` (a list, never a shell string). Raises ``TimedOut`` or ``OutputTooLarge``.

    The child is killed on either. stderr beyond ``max_stderr`` is cut, not an error.
    """
    proc = subprocess.Popen(  # noqa: S603 - argument list, no shell
        list(args),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=dict(env) if env is not None else None,
        creationflags=creationflags,
    )
    if proc.stdin is None or proc.stdout is None or proc.stderr is None:
        proc.kill()
        raise RuntimeError("pipes were not created")
    out: list[bytes] = []
    err: list[bytes] = []
    out_over = threading.Event()
    err_over = threading.Event()
    readers = [
        threading.Thread(target=_read, args=(proc.stdout, max_stdout, out, out_over), daemon=True),
        threading.Thread(target=_read, args=(proc.stderr, max_stderr, err, err_over), daemon=True),
    ]
    for t in readers:
        t.start()
    stdin_pipe = proc.stdin

    def feed() -> None:
        try:
            stdin_pipe.write(stdin)
            stdin_pipe.close()
        except OSError:
            pass  # the child ended early; its exit code tells the story

    threading.Thread(target=feed, daemon=True).start()

    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                code = proc.wait(timeout=0.05)
                break
            except subprocess.TimeoutExpired:
                pass
            if out_over.is_set():
                raise OutputTooLarge(f"output above {max_stdout} bytes")
            if time.monotonic() > deadline:
                raise TimedOut("time limit reached")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        for t in readers:
            t.join(2)
        for pipe in (proc.stdout, proc.stderr, proc.stdin):
            with contextlib.suppress(OSError):
                pipe.close()
    if out_over.is_set():
        raise OutputTooLarge(f"output above {max_stdout} bytes")
    return Completed(code, b"".join(out), b"".join(err), err_over.is_set())
