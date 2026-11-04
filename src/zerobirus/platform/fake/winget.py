"""A synthetic list of app updates for tests and ``--demo``. Nothing is installed."""

from __future__ import annotations

from zerobirus.core.allup import Upgrade


class FakePackageUpdater:
    def __init__(self, upgrades: tuple[Upgrade, ...] | None = None) -> None:
        self.pending: dict[str, Upgrade] = {
            u.id: u
            for u in (
                upgrades
                if upgrades is not None
                else (
                    Upgrade("Navegador demo", "Demo.Browser", "130.0", "131.0", "winget"),
                    Upgrade("Leitor demo", "Demo.Player", "2.1", "2.2", "winget"),
                    Upgrade("Editor demo", "Demo.Editor", "1.90", "1.91", "winget"),
                )
            )
        }
        self.installed: list[str] = []
        self.fail: set[str] = set()  # ids whose update "succeeds" but does not stick
        self.error: set[str] = set()  # ids whose update fails

    def list_upgrades(self) -> tuple[Upgrade, ...]:
        return tuple(self.pending.values())

    def upgrade(self, package_id: str) -> tuple[bool, str]:
        self.installed.append(package_id)
        if package_id in self.error:
            return False, "Falhou a instalação."
        if package_id not in self.fail:
            self.pending.pop(package_id, None)
        return True, "Instalado com sucesso."
