"""One module per check. Each takes an Inspector and returns a CheckResult."""

from __future__ import annotations

from collections.abc import Callable

from zerobirus.core.models import CheckResult
from zerobirus.platform.base import Inspector
from zerobirus.scanners import (
    defender,
    files,
    hosts,
    network,
    processes,
    services,
    startup,
    tasks,
    wmi,
)

Scanner = Callable[[Inspector], CheckResult]

#: check name to scanner, in the order shown to the user.
SCANNERS: dict[str, Scanner] = {
    processes.CHECK: processes.scan,
    startup.CHECK: startup.scan,
    tasks.CHECK: tasks.scan,
    services.CHECK: services.scan,
    files.CHECK: files.scan,
    network.CHECK: network.scan,
    defender.CHECK: defender.scan,
    hosts.CHECK: hosts.scan,
    wmi.CHECK: wmi.scan,
}

#: Short pt-PT title of each check (shown in reports and the interface).
TITLES: dict[str, str] = {
    processes.CHECK: "Processos em execução",
    startup.CHECK: "Arranque com o Windows",
    tasks.CHECK: "Tarefas agendadas",
    services.CHECK: "Serviços",
    files.CHECK: "Programas em pastas graváveis",
    network.CHECK: "Ligações de rede",
    defender.CHECK: "Microsoft Defender",
    hosts.CHECK: "Ficheiro hosts",
    wmi.CHECK: "Assinaturas WMI",
}
