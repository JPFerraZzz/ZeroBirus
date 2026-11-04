"""Reversible system settings the person can choose to change (Modo Jogo, D-017).

Every tweak is a fixed entry of this catalog: an exact registry value to set, or one of the
known power plans. The removal engine accepts a tweak item only if it matches its catalog
entry parameter for parameter, so a plan altered after the fact (a different key, a different
value) is refused. Nothing here touches the system: it only describes changes and builds the
plan items; ``remediation/engine.py`` does the work, saves the previous value first, re-reads
the result and can put the old value back.

Never in this catalog, at any level: antivirus, Defender, security updates, firewall and
Windows files (ROADMAP, MegaTweaker conditions).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from zerobirus.core.models import Level
from zerobirus.core.plan import ActionType, PlanItem, item_id

HIGH_PERFORMANCE_PLAN = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
POWER_PLANS = frozenset({HIGH_PERFORMANCE_PLAN})


class Danger(StrEnum):
    SEGURO = "seguro"
    MODERADO = "moderado"


@dataclass(frozen=True, slots=True)
class Tweak:
    id: str
    title: str
    why: str
    danger: Danger
    action: ActionType
    params: tuple[tuple[str, str], ...]
    needs_admin: bool = False
    needs_reboot: bool = False

    def param(self, key: str, default: str = "") -> str:
        return next((v for k, v in self.params if k == key), default)


def _reg(root: str, key: str, value: str, data: int, **extra: str) -> tuple[tuple[str, str], ...]:
    pairs = {"root": root, "key": key, "value": value, "type": "dword", "data": str(data)}
    return tuple(sorted({**pairs, **extra}.items()))


FPS_TWEAKS: tuple[Tweak, ...] = (
    Tweak(
        "game_mode",
        "Modo de Jogo do Windows",
        "Liga o Modo de Jogo: o Windows dá prioridade ao jogo e adia tarefas em segundo plano.",
        Danger.SEGURO,
        ActionType.SET_REGISTRY_VALUE,
        _reg("HKCU", r"Software\Microsoft\GameBar", "AutoGameModeEnabled", 1, tweak="game_mode"),
    ),
    Tweak(
        "gamebar_capture",
        "Captura de ecrã e vídeo da Xbox Game Bar",
        "Desliga a gravação em segundo plano da Game Bar, que gasta processador e disco.",
        Danger.SEGURO,
        ActionType.SET_REGISTRY_VALUE,
        _reg("HKCU", r"System\GameConfigStore", "GameDVR_Enabled", 0, tweak="gamebar_capture"),
    ),
    Tweak(
        "app_capture",
        "Captura de jogos em segundo plano",
        "Impede o Windows de gravar o jogo em segundo plano.",
        Danger.SEGURO,
        ActionType.SET_REGISTRY_VALUE,
        _reg(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\GameDVR",
            "AppCaptureEnabled",
            0,
            tweak="app_capture",
        ),
    ),
    Tweak(
        "power_high",
        "Plano de energia de alto desempenho",
        "O processador não baixa a velocidade para poupar energia. Gasta mais bateria e aquece "
        "mais; em portáteis só compensa ligado à corrente.",
        Danger.MODERADO,
        ActionType.SET_POWER_PLAN,
        (("plan", HIGH_PERFORMANCE_PLAN), ("tweak", "power_high")),
    ),
    Tweak(
        "hags",
        "Agendamento da GPU por hardware",
        "A placa gráfica gere a sua própria memória de vídeo. Só aparece se o PC e o driver o "
        "suportam. Precisa de reiniciar o PC.",
        Danger.MODERADO,
        ActionType.SET_REGISTRY_VALUE,
        _reg(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
            "HwSchMode",
            2,
            requires_existing="1",
            tweak="hags",
        ),
        needs_admin=True,
        needs_reboot=True,
    ),
)
CATALOG: dict[str, Tweak] = {t.id: t for t in FPS_TWEAKS}
TWEAK_ACTIONS = frozenset({ActionType.SET_REGISTRY_VALUE, ActionType.SET_POWER_PLAN})


def tweak_item(tweak: Tweak, *, selected: bool = False) -> PlanItem:
    """The plan item for one catalog entry. Never selected unless the caller says so."""
    return PlanItem(
        id=item_id(tweak.action, tweak.params),
        action=tweak.action,
        target=tweak.title,
        params=tweak.params,
        level=Level.OK,
        why=tweak.why,
        finding_id=f"tweak:{tweak.id}",
        default_selected=selected,
    )


def catalog_tweak_for(item: PlanItem) -> Tweak | None:
    """The catalog entry that this item is exactly equal to, or ``None`` (refuse it)."""
    tweak = CATALOG.get(item.param("tweak"))
    if tweak is None or item.action is not tweak.action:
        return None
    return tweak if tuple(sorted(item.params)) == tuple(sorted(tweak.params)) else None


def wanted_value(item: PlanItem) -> str:
    """What the setting should read as after the change (a number or a plan GUID)."""
    return item.param("plan") if item.action is ActionType.SET_POWER_PLAN else item.param("data")
