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
    AGRESSIVO = "agressivo"


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
    category: str = ""  # MegaTweaker groups; empty for the FPS Optimizer list

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
CAT_PRIVACY = "Privacidade e recomendações"
CAT_LOOK = "Aspeto e animações"
CAT_GAMING = "Jogos e rede"
CAT_SYSTEM = "Sistema e arranque"
CATEGORIES = (CAT_PRIVACY, CAT_LOOK, CAT_GAMING, CAT_SYSTEM)

_CDM = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
_EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Explorer"
_PROFILE = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"


def _mega(
    tid: str,
    category: str,
    title: str,
    why: str,
    danger: Danger,
    root: str,
    key: str,
    value: str,
    data: int,
    *,
    reboot: bool = False,
) -> Tweak:
    return Tweak(
        tid,
        title,
        why,
        danger,
        ActionType.SET_REGISTRY_VALUE,
        _reg(root, key, value, data, tweak=tid),
        needs_admin=root == "HKLM",
        needs_reboot=reboot,
        category=category,
    )


# Inspired by the categories of winutil (idea only, reimplemented). Every entry is a single
# DWORD value; nothing here stops a service or touches security (ROADMAP, decision 3).
MEGA_TWEAKS: tuple[Tweak, ...] = (
    _mega(
        "ad_id",
        CAT_PRIVACY,
        "Identificador de publicidade",
        "Os programas deixam de usar um identificador teu para te mostrar anúncios à medida.",
        Danger.SEGURO,
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
        "Enabled",
        0,
    ),
    _mega(
        "tailored",
        CAT_PRIVACY,
        "Experiências personalizadas com dados de diagnóstico",
        "O Windows deixa de usar os dados de diagnóstico para te sugerir dicas e anúncios.",
        Danger.SEGURO,
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\Privacy",
        "TailoredExperiencesWithDiagnosticDataEnabled",
        0,
    ),
    _mega(
        "start_suggestions",
        CAT_PRIVACY,
        "Sugestões no menu Iniciar",
        "Tira as aplicações sugeridas e promovidas do menu Iniciar.",
        Danger.SEGURO,
        "HKCU",
        _CDM,
        "SystemPaneSuggestionsEnabled",
        0,
    ),
    _mega(
        "promoted_apps",
        CAT_PRIVACY,
        "Instalação automática de aplicações promovidas",
        "O Windows deixa de instalar sozinho jogos e aplicações patrocinadas.",
        Danger.SEGURO,
        "HKCU",
        _CDM,
        "SilentInstalledAppsEnabled",
        0,
    ),
    _mega(
        "windows_tips",
        CAT_PRIVACY,
        "Dicas e sugestões do Windows",
        "Desliga as notificações de dicas e sugestões.",
        Danger.SEGURO,
        "HKCU",
        _CDM,
        "SubscribedContent-338389Enabled",
        0,
    ),
    _mega(
        "lock_screen_ads",
        CAT_PRIVACY,
        "Publicidade no ecrã de bloqueio",
        "Tira as imagens e sugestões rotativas do ecrã de bloqueio.",
        Danger.SEGURO,
        "HKCU",
        _CDM,
        "RotatingLockScreenOverlayEnabled",
        0,
    ),
    _mega(
        "bing_search",
        CAT_PRIVACY,
        "Resultados da web na pesquisa do Iniciar",
        "A pesquisa do Iniciar procura só no PC, sem enviar o que escreves para a web.",
        Danger.SEGURO,
        "HKCU",
        r"Software\Policies\Microsoft\Windows\Explorer",
        "DisableSearchBoxSuggestions",
        1,
    ),
    _mega(
        "telemetry",
        CAT_PRIVACY,
        "Dados de diagnóstico enviados à Microsoft",
        "Pede o mínimo de dados de diagnóstico. Nas edições Home o Windows ignora o nível zero e "
        "envia o básico.",
        Danger.MODERADO,
        "HKLM",
        r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "AllowTelemetry",
        0,
    ),
    _mega(
        "transparency",
        CAT_LOOK,
        "Efeitos de transparência",
        "Desliga a transparência das janelas e da barra: menos trabalho para a placa gráfica.",
        Danger.SEGURO,
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        "EnableTransparency",
        0,
    ),
    _mega(
        "taskbar_anim",
        CAT_LOOK,
        "Animações da barra de tarefas",
        "A barra de tarefas deixa de animar ao abrir e fechar programas.",
        Danger.SEGURO,
        "HKCU",
        _EXPLORER + r"\Advanced",
        "TaskbarAnimations",
        0,
    ),
    _mega(
        "visual_fx",
        CAT_LOOK,
        "Efeitos visuais para melhor desempenho",
        "Escolhe o perfil de melhor desempenho: sombras, animações e suavização de letras "
        "desaparecem. O Windows fica com aspeto mais simples.",
        Danger.AGRESSIVO,
        "HKCU",
        _EXPLORER + r"\VisualEffects",
        "VisualFXSetting",
        2,
    ),
    _mega(
        "fullscreen_opt",
        CAT_GAMING,
        "Otimizações de ecrã inteiro",
        "Os jogos em ecrã inteiro usam o modo clássico, que costuma dar menos atraso.",
        Danger.MODERADO,
        "HKCU",
        r"System\GameConfigStore",
        "GameDVR_FSEBehaviorMode",
        2,
    ),
    _mega(
        "net_throttle",
        CAT_GAMING,
        "Limite de rede para multimédia",
        "Tira o limite que o Windows põe à rede enquanto reproduz multimédia. Pode ajudar a "
        "baixar o atraso nos jogos online.",
        Danger.MODERADO,
        "HKLM",
        _PROFILE,
        "NetworkThrottlingIndex",
        0xFFFFFFFF,
    ),
    _mega(
        "responsiveness",
        CAT_GAMING,
        "Reserva de processador para tarefas em segundo plano",
        "Põe a zero a parte do processador reservada ao que corre em segundo plano. Pode "
        "estragar o som e o vídeo de outros programas enquanto jogas.",
        Danger.AGRESSIVO,
        "HKLM",
        _PROFILE,
        "SystemResponsiveness",
        0,
    ),
    _mega(
        "startup_delay",
        CAT_SYSTEM,
        "Atraso dos programas de arranque",
        "Tira o atraso que o Windows põe antes de abrir os programas de arranque.",
        Danger.SEGURO,
        "HKCU",
        _EXPLORER + r"\Serialize",
        "StartupDelayInMSec",
        0,
    ),
    _mega(
        "fast_startup",
        CAT_SYSTEM,
        "Arranque rápido",
        "Desliga o arranque rápido: o PC desliga e arranca de verdade. Resolve problemas de "
        "drivers e de atualizações que não aplicam, mas o arranque demora mais.",
        Danger.MODERADO,
        "HKLM",
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Power",
        "HiberbootEnabled",
        0,
        reboot=True,
    ),
)
ALL_TWEAKS: tuple[Tweak, ...] = FPS_TWEAKS + MEGA_TWEAKS
CATALOG: dict[str, Tweak] = {t.id: t for t in ALL_TWEAKS}
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
