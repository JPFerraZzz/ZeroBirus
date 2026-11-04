"""A fixed memory reading for tests and ``--demo``."""

from __future__ import annotations

from zerobirus.core.ram import MEGA, MemoryProcess, MemorySnapshot


def _proc(pid: int, name: str, path: str | None, mb: int) -> MemoryProcess:
    return MemoryProcess(pid, name, path, mb * MEGA)


class FakeMemoryProbe:
    def __init__(self, snapshot: MemorySnapshot | None = None) -> None:
        self._snapshot = snapshot or MemorySnapshot(
            total=16 * 1024 * MEGA,
            available=3 * 1024 * MEGA,
            processes=(
                _proc(4101, "chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe", 2400),
                _proc(4102, "Discord.exe", r"C:\Users\Ana\AppData\Local\Discord\Discord.exe", 640),
                _proc(
                    4103, "Spotify.exe", r"C:\Users\Ana\AppData\Roaming\Spotify\Spotify.exe", 420
                ),
                _proc(
                    4104, "OneDrive.exe", r"C:\Users\Ana\AppData\Local\OneDrive\OneDrive.exe", 180
                ),
                _proc(4, "System", None, 12),
                _proc(612, "svchost.exe", r"C:\Windows\System32\svchost.exe", 300),
            ),
        )

    def snapshot(self) -> MemorySnapshot:
        return self._snapshot
