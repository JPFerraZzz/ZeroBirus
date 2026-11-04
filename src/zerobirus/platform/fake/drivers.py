"""A synthetic driver reading for tests and ``--demo``."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def demo_drivers() -> dict[str, Any]:
    return {
        "installed": [
            {
                "name": "Placa gráfica de demonstração",
                "manufacturer": "NVIDIA",
                "version": "31.0.15",
                "date": "2026-06-02",
                "class": "DISPLAY",
            },
            {
                "name": "Placa de rede de demonstração",
                "manufacturer": "Realtek",
                "version": "10.50",
                "date": "2021-02-11",
                "class": "NET",
            },
        ],
        "pending": [{"title": "Realtek - Net - 10.70 (driver de demonstração)"}],
    }


class FakeDriverProbe:
    def __init__(self, reading: Mapping[str, Any] | None = None) -> None:
        self._reading = reading if reading is not None else demo_drivers()

    def read(self) -> Mapping[str, Any]:
        return self._reading
