"""A synthetic BigDiag reading for tests and ``--demo``. No real machine is described."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

GB = 1024**3


def demo_reading() -> dict[str, Any]:
    return {
        "os": {
            "caption": "Microsoft Windows 11 Pro",
            "build": "26100",
            "uptime_days": 21,
            "last_update": "2026-09-18",
        },
        "cpu": [{"name": "Processador de demonstração", "cores": 6, "threads": 12}],
        "cpu_temp_c": None,
        "ram_modules": [{"speed_mhz": 3200}, {"speed_mhz": 3200}],
        "disks": [
            {
                "name": "SSD de demonstração",
                "media": "SSD",
                "size": 500 * GB,
                "health": "Healthy",
                "wear_percent": 12,
                "temperature_c": 41,
                "power_on_hours": 5120,
                "read_errors": 0,
                "write_errors": 0,
            },
            {
                "name": "Disco rígido de demonstração",
                "media": "HDD",
                "size": 2000 * GB,
                "health": "Warning",
                "temperature_c": 38,
                "read_errors": 4,
                "write_errors": 0,
            },
        ],
        "volumes": [
            {"letter": "C", "size": 500 * GB, "free": 38 * GB},
            {"letter": "D", "size": 2000 * GB, "free": 1200 * GB},
        ],
        "gpus": [
            {
                "name": "Placa gráfica de demonstração",
                "driver_version": "31.0.1",
                "driver_date": "2026-06-02",
            }
        ],
        "mrt": {"version": "5.130", "last_run": "2026-10-14", "outcome": "clean"},
        "failures": {
            "unexpected_shutdowns": 2,
            "bugchecks": 0,
            "app_crashes": 6,
            "disk_errors": 0,
        },
    }


class FakeDiagProbe:
    def __init__(self, reading: Mapping[str, Any] | None = None) -> None:
        self._reading = reading if reading is not None else demo_reading()

    def read(self) -> Mapping[str, Any]:
        return self._reading
