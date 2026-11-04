"""From findings to a plan the user can authorise, and the authorised plan itself.

BRIEF section 5, stage 3: the plan lists exactly what would change, grouped by type; items the
person did not approve do not exist for stage 4. The authorised plan is an immutable object
carrying only the approved items; it is the single input the removal layer accepts, and that
layer re-checks every item against ``core.safety`` regardless of what the interface said.

Pure data and rules: no I/O and no OS access, so everything here runs and is tested on Linux.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum

from zerobirus.core.models import (
    CheckResult,
    Finding,
    Level,
    SignatureStatus,
    TempEntry,
)
from zerobirus.core.risk import Risk, risk_of
from zerobirus.core.safety import (
    SignerKind,
    SystemContext,
    is_no_image_process_name,
    is_protected_path,
    is_protected_process,
    normalize_windows_path,
)
from zerobirus.core.snapshot import Snapshot

PLAN_SCHEMA_VERSION = 1
IMPACT_LIMIT = 20  # more items than this, or any folder, asks for a second confirmation


class ActionType(StrEnum):
    KILL_PROCESS = "kill_process"
    REMOVE_TASK = "remove_task"
    DISABLE_SERVICE = "disable_service"
    REMOVE_REGISTRY_VALUE = "remove_registry_value"
    QUARANTINE_STARTUP_SHORTCUT = "quarantine_startup_shortcut"
    REMOVE_WMI_BINDING = "remove_wmi_binding"
    QUARANTINE_FILE = "quarantine_file"
    QUARANTINE_FOLDER = "quarantine_folder"
    REMOVE_DEFENDER_EXCLUSION = "remove_defender_exclusion"
    REMOVE_HOSTS_LINE = "remove_hosts_line"
    ADD_HOSTS_BLOCK = "add_hosts_block"
    ADD_FIREWALL_BLOCK = "add_firewall_block"
    CLEAN_TEMP_FILE = "clean_temp_file"
    CLEAN_TEMP_FOLDER = "clean_temp_folder"
    # Reversible settings from the fixed catalog in core/tweaks.py (Modo Jogo).
    SET_REGISTRY_VALUE = "set_registry_value"
    SET_POWER_PLAN = "set_power_plan"


# Groups in the order of BRIEF section 5 stage 3, with the text shown to the person (pt-PT).
GROUPS: tuple[tuple[str, tuple[ActionType, ...]], ...] = (
    ("Processos", (ActionType.KILL_PROCESS,)),
    ("Tarefas agendadas", (ActionType.REMOVE_TASK,)),
    ("Serviços", (ActionType.DISABLE_SERVICE,)),
    ("Valores de registo", (ActionType.REMOVE_REGISTRY_VALUE,)),
    ("Atalhos de Arranque", (ActionType.QUARANTINE_STARTUP_SHORTCUT,)),
    ("Assinaturas WMI", (ActionType.REMOVE_WMI_BINDING,)),
    ("Ficheiros e pastas", (ActionType.QUARANTINE_FILE, ActionType.QUARANTINE_FOLDER)),
    ("Exclusões do Defender", (ActionType.REMOVE_DEFENDER_EXCLUSION,)),
    ("Entradas do ficheiro hosts", (ActionType.REMOVE_HOSTS_LINE, ActionType.ADD_HOSTS_BLOCK)),
    ("Bloqueios de firewall", (ActionType.ADD_FIREWALL_BLOCK,)),
    (
        "Ficheiros temporários (opcional)",
        (ActionType.CLEAN_TEMP_FILE, ActionType.CLEAN_TEMP_FOLDER),
    ),
    ("Definições do Windows", (ActionType.SET_REGISTRY_VALUE, ActionType.SET_POWER_PLAN)),
)
ACTION_VERB = {
    ActionType.KILL_PROCESS: "Terminar o processo",
    ActionType.REMOVE_TASK: "Remover a tarefa agendada",
    ActionType.DISABLE_SERVICE: "Parar e desativar o serviço",
    ActionType.REMOVE_REGISTRY_VALUE: "Remover o valor de registo",
    ActionType.QUARANTINE_STARTUP_SHORTCUT: "Mover para a quarentena o atalho de Arranque",
    ActionType.REMOVE_WMI_BINDING: "Remover a assinatura WMI",
    ActionType.QUARANTINE_FILE: "Mover para a quarentena o ficheiro",
    ActionType.QUARANTINE_FOLDER: "Mover para a quarentena a pasta",
    ActionType.REMOVE_DEFENDER_EXCLUSION: "Remover a exclusão do Defender",
    ActionType.REMOVE_HOSTS_LINE: "Remover a linha do ficheiro hosts",
    ActionType.ADD_HOSTS_BLOCK: "Bloquear no ficheiro hosts o nome",
    ActionType.ADD_FIREWALL_BLOCK: "Bloquear na firewall o endereço",
    ActionType.CLEAN_TEMP_FILE: "Mover para a quarentena o ficheiro temporário",
    ActionType.CLEAN_TEMP_FOLDER: "Mover para a quarentena a pasta temporária",
    ActionType.SET_REGISTRY_VALUE: "Mudar a definição",
    ActionType.SET_POWER_PLAN: "Mudar o plano de energia para",
}

# Labels the Defender scanner puts in ``exclusion_kind`` (pt-PT) to the names Defender uses.
EXCLUSION_KINDS = {"pasta": "path", "extensão": "extension", "processo": "process", "IP": "ip"}

TEMP_MIN_AGE_DAYS = 2
TEMP_MAX_ITEMS = 200
TEMP_WHY = (
    "Ficheiro temporário que nenhum programa mexeu há mais de {days} dias. É seguro mover para "
    "a quarentena: dá para desfazer, e só se apaga de vez se pedires."
)


@dataclass(frozen=True, slots=True)
class PlanItem:
    """One change the removal layer may perform if, and only if, the person approves it.

    ``params`` are the exact facts the removal layer works from (key path, value name, task
    path, pid and image path...). They are data copied from the finding, never commands.
    """

    id: str
    action: ActionType
    target: str  # what the person sees: a path, a name
    params: tuple[tuple[str, str], ...]
    level: Level
    why: str  # the finding's explanation, pt-PT
    finding_id: str
    default_selected: bool
    sha256: str | None = None
    # The five-level risk (core/risk.py); None for optional cleaning, which is outside the table.
    risk: Risk | None = None

    def param(self, key: str, default: str = "") -> str:
        return next((v for k, v in self.params if k == key), default)

    @property
    def description(self) -> str:
        return f"{ACTION_VERB[self.action]} {self.target}"


@dataclass(frozen=True, slots=True)
class NotPlannable:
    """A finding that cannot become an action, and why (always shown, never silent)."""

    finding_id: str
    item: str
    reason: str


@dataclass(frozen=True, slots=True)
class Plan:
    items: tuple[PlanItem, ...]
    not_plannable: tuple[NotPlannable, ...]

    def by_id(self) -> dict[str, PlanItem]:
        return {i.id: i for i in self.items}

    def groups(self) -> list[tuple[str, tuple[PlanItem, ...]]]:
        out: list[tuple[str, tuple[PlanItem, ...]]] = []
        for title, actions in GROUPS:
            members = tuple(i for i in self.items if i.action in actions)
            if members:
                out.append((title, members))
        return out

    def risk_groups(self) -> list[tuple[Risk, tuple[PlanItem, ...]]]:
        """Items of the risk table, most serious level first. Optional cleaning is not in it."""
        out: list[tuple[Risk, tuple[PlanItem, ...]]] = []
        for risk in sorted(Risk, key=lambda r: -r.rank):
            members = tuple(i for i in self.items if i.risk is risk)
            if members:
                out.append((risk, members))
        return out

    def temp_items(self) -> tuple[PlanItem, ...]:
        return tuple(i for i in self.items if i.risk is None)


def item_id(action: ActionType, params: Iterable[tuple[str, str]]) -> str:
    """Stable id: the same action on the same target always gets the same id."""
    canonical = json.dumps([action.value, sorted(params)], ensure_ascii=True, separators=(",", ":"))
    return "i-" + hashlib.sha256(canonical.encode("ascii")).hexdigest()[:12]


def digest(items: Iterable[PlanItem]) -> str:
    """A fingerprint of a set of items (ids, actions and params), order independent."""
    rows = sorted([i.id, i.action.value, sorted(i.params), i.sha256 or ""] for i in items)
    text = json.dumps([PLAN_SCHEMA_VERSION, rows], ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("ascii")).hexdigest()


_REG_SOURCE = re.compile(
    r"^(?P<root>HKLM|HKU\\S-1-5-21-[0-9-]+)\\(?P<path>.+?) \((?P<view>64|32)\)$"
)
_REMOVABLE_REGISTRY_KINDS = frozenset({"run", "runonce", "policies_run", "ifeo"})


def _item(
    action: ActionType,
    target: str,
    params: dict[str, str],
    finding: Finding,
    *,
    default_selected: bool | None = None,
) -> PlanItem:
    pairs = tuple(sorted(params.items()))
    risk = risk_of(finding)
    if default_selected is None:
        default_selected = risk is not None and risk.preselected
    return PlanItem(
        id=item_id(action, pairs),
        action=action,
        target=target,
        params=pairs,
        level=finding.level,
        why=finding.description,
        finding_id=finding.id,
        default_selected=default_selected,
        sha256=finding.sha256,
        risk=risk,
    )


def _signer_of(snapshot: Snapshot | None, path: str | None) -> SignerKind | None:
    """The signer of ``path`` if a signature was actually checked, else None (fail closed)."""
    if snapshot is None or not path:
        return None
    key = normalize_windows_path(path)
    for sig in snapshot.signatures:
        if normalize_windows_path(sig.path) == key and sig.status is not SignatureStatus.UNKNOWN:
            return sig.kind
    return None


class _Builder:
    def __init__(self, ctx: SystemContext, snapshot: Snapshot | None) -> None:
        self.ctx = ctx
        self.snapshot = snapshot
        self.items: dict[str, PlanItem] = {}
        self.refused: list[NotPlannable] = []
        self.registry_seen: set[tuple[str, str, str]] = set()

    def add(self, item: PlanItem) -> None:
        self.items.setdefault(item.id, item)

    def refuse(self, finding: Finding, reason: str) -> None:
        self.refused.append(NotPlannable(finding.id, finding.item, reason))

    def protected(self, path: str) -> bool:
        return is_protected_path(path, self.ctx, signer=_signer_of(self.snapshot, path))

    # per kind -------------------------------------------------------------------------

    def process(self, f: Finding) -> None:
        name, path = f.subject_get("name"), f.subject_get("path")
        pid = f.subject_get("pid")
        if not pid.isdigit():
            return self.refuse(f, "não há identificador do processo")
        if is_protected_process(name, path or None, self.ctx, pid=int(pid)):
            return self.refuse(f, "é um processo protegido do Windows ou da própria ferramenta")
        self.add(
            _item(
                ActionType.KILL_PROCESS,
                f"{name} (PID {pid})",
                {"pid": pid, "name": name, "path": path},
                f,
            )
        )
        if path and not is_no_image_process_name(name):
            self.file(f, path)

    def file(self, f: Finding, path: str) -> None:
        if not path:
            return self.refuse(f, "não há caminho do ficheiro")
        if self.protected(path):
            return self.refuse(
                f, "o caminho está protegido (Windows, pastas pessoais ou antivírus)"
            )
        self.add(_item(ActionType.QUARANTINE_FILE, path, {"path": path}, f))

    def file_finding(self, f: Finding) -> None:
        self.file(f, f.subject_get("path"))

    def autorun(self, f: Finding) -> None:
        kind = f.subject_get("autorun_kind")
        if kind == "startup_folder":
            path = f.subject_get("path")
            if not path or self.protected(path):
                return self.refuse(f, "o atalho está num caminho protegido ou desconhecido")
            self.add(_item(ActionType.QUARANTINE_STARTUP_SHORTCUT, path, {"path": path}, f))
            return None
        if kind not in _REMOVABLE_REGISTRY_KINDS:
            return self.refuse(
                f,
                "valor de arranque do Windows (Winlogon ou AppInit): não é removido "
                "automaticamente, ver o conselho",
            )
        m = _REG_SOURCE.match(f.subject_get("source"))
        name = f.subject_get("name")
        if m is None or not name:
            return self.refuse(f, "não foi possível identificar a chave de registo")
        value_name = "Debugger" if kind == "ifeo" else name
        key = m.group("path") if kind != "ifeo" else m.group("path") + "\\" + name
        # The Run keys are shared by the 64 and 32 bit views: one value, one item (the 64 view
        # wins), otherwise the second removal finds it already gone.
        same = (m.group("root").lower(), key.lower(), value_name.lower())
        if same in self.registry_seen and m.group("view") == "32":
            return None
        self.registry_seen.add(same)
        self.add(
            _item(
                ActionType.REMOVE_REGISTRY_VALUE,
                f"{m.group('root')}\\{key} : {value_name}",
                {"root": m.group("root"), "key": key, "view": m.group("view"), "value": value_name},
                f,
            )
        )
        return None

    def task(self, f: Finding) -> None:
        folder, name = f.subject_get("folder"), f.subject_get("name")
        if not name:
            return self.refuse(f, "não há nome da tarefa")
        self.add(
            _item(ActionType.REMOVE_TASK, f"{folder}{name}", {"folder": folder, "name": name}, f)
        )
        if f.path and not self.protected(f.path) and f.path[1:3] == ":\\":
            self.file(f, f.path)

    def service(self, f: Finding) -> None:
        name, image = f.subject_get("name"), f.subject_get("image")
        if image and self.protected(image):
            return self.refuse(f, "o ficheiro do serviço está num caminho protegido")
        self.add(_item(ActionType.DISABLE_SERVICE, name, {"name": name, "image": image}, f))
        if image and image[1:3] == ":\\":
            self.file(f, image)
        return None

    def wmi(self, f: Finding) -> None:
        params = {
            "filter": f.subject_get("filter"),
            "consumer": f.subject_get("consumer"),
            "consumer_class": f.subject_get("consumer_class"),
        }
        self.add(
            _item(
                ActionType.REMOVE_WMI_BINDING,
                f"{params['consumer']} ({params['filter']})",
                params,
                f,
            )
        )

    def defender_exclusion(self, f: Finding) -> None:
        kind, value = f.subject_get("exclusion_kind"), f.subject_get("value")
        self.add(
            _item(
                ActionType.REMOVE_DEFENDER_EXCLUSION,
                f"{value} ({kind})",
                {"exclusion_kind": kind, "value": value},
                f,
            )
        )

    def hosts_line(self, f: Finding) -> None:
        line = f.subject_get("line")
        self.add(_item(ActionType.REMOVE_HOSTS_LINE, line, {"line": line}, f))

    def connection(self, f: Finding) -> None:
        """Firewall blocks are not offered in Alpha 1.0: the rule is created on Windows but the
        independent check could not confirm it yet (docs/STATUS.md). The connection still shows
        in the diagnosis, and the process behind it is planned for removal."""
        return


def temp_items(entries: Iterable[TempEntry], ctx: SystemContext) -> list[PlanItem]:
    """Optional cleaning of old Temp entries. Never pre-selected; protected paths are skipped.

    Same quarantine path as everything else: nothing is deleted. Biggest entries first, capped,
    so the list stays readable; the rest simply stays where it is.
    """
    out: list[PlanItem] = []
    for e in sorted(entries, key=lambda x: -x.size):
        if e.age_days < TEMP_MIN_AGE_DAYS or is_protected_path(e.path, ctx):
            continue
        action = ActionType.CLEAN_TEMP_FOLDER if e.is_dir else ActionType.CLEAN_TEMP_FILE
        pairs = (("path", e.path),)
        out.append(
            PlanItem(
                id=item_id(action, pairs),
                action=action,
                target=e.path,
                params=pairs,
                level=Level.OK,
                why=TEMP_WHY.format(days=TEMP_MIN_AGE_DAYS),
                finding_id="temp",
                default_selected=False,
            )
        )
        if len(out) >= TEMP_MAX_ITEMS:
            break
    return out


def build_plan(
    checks: Iterable[CheckResult],
    ctx: SystemContext,
    snapshot: Snapshot | None = None,
    temp_entries: Iterable[TempEntry] = (),
) -> Plan:
    """Turn findings that deserve action into proposed plan items.

    GRAVE and CRITICO items come pre-selected (D-015); the rest never do. Anything protected by
    ``core.safety`` is not planned and appears in ``not_plannable`` with the reason. OK and
    NAO_VERIFICADO findings never become actions.
    """
    b = _Builder(ctx, snapshot)
    handlers: dict[str, Callable[[Finding], None]] = {
        "process": b.process,
        "autorun": b.autorun,
        "task": b.task,
        "service": b.service,
        "file": b.file_finding,
        "wmi_subscription": b.wmi,
        "defender_exclusion": b.defender_exclusion,
        "hosts_line": b.hosts_line,
        "connection": b.connection,
    }
    for check in checks:
        for f in check.findings:
            if f.level not in (Level.SUSPEITO, Level.CONFERIR):
                continue
            handler = handlers.get(f.subject_get("kind"))
            if handler is None:
                if f.subject_get("kind"):
                    b.refuse(f, "este tipo de achado não tem ação automática")
                continue
            handler(f)
    for item in temp_items(temp_entries, ctx):
        b.add(item)
    return Plan(tuple(b.items.values()), tuple(b.refused))


# The authorised plan ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthorizedPlan:
    """What the person approved. Immutable. The only input accepted by stage 4.

    Build it with ``authorize``. ``verify`` recomputes the fingerprint, so a plan altered after
    authorisation (a different item list under the same digest) is detected and refused.
    """

    session_id: str
    authorised_at: str
    items: tuple[PlanItem, ...]
    plan_digest: str

    def verify(self) -> bool:
        return digest(self.items) == self.plan_digest

    def contains(self, item: PlanItem) -> bool:
        return self.verify() and any(i == item for i in self.items)

    def contains_id(self, item_id_: str) -> bool:
        return self.verify() and any(i.id == item_id_ for i in self.items)


def needs_extra_confirmation(items: Iterable[PlanItem]) -> bool:
    """Big plans, and any plan that moves a whole folder, ask for a second confirmation."""
    chosen = list(items)
    return len(chosen) > IMPACT_LIMIT or any(
        i.action is ActionType.QUARANTINE_FOLDER for i in chosen
    )


def authorize(
    plan: Plan,
    approved_ids: Iterable[str],
    *,
    session_id: str,
    authorised_at: str,
    extra_confirmation_count: int | None = None,
) -> AuthorizedPlan:
    """Create the authorised plan from the approved ids.

    Unknown ids are an error (never silently ignored). An empty selection is an error: there
    is nothing to authorise. When the plan needs a second confirmation, the person must have
    typed the number of items (``extra_confirmation_count``).
    """
    known = plan.by_id()
    ids = list(dict.fromkeys(approved_ids))
    unknown = [i for i in ids if i not in known]
    if unknown:
        raise ValueError(f"ids that are not in the plan: {unknown}")
    if not ids:
        raise ValueError("nothing was approved")
    chosen = tuple(known[i] for i in ids)
    if needs_extra_confirmation(chosen) and extra_confirmation_count != len(chosen):
        raise ValueError("this plan needs the second confirmation with the number of items")
    return AuthorizedPlan(session_id, authorised_at, chosen, digest(chosen))


def render_plan_text(
    plan: Plan,
    approved_ids: Iterable[str],
    *,
    session_id: str,
    authorised_at: str,
    version: str,
) -> str:
    """The text saved to the Desktop BEFORE anything changes (pt-PT)."""
    approved = set(approved_ids)
    lines = [
        f"ZeroBirus {version}: plano de remoção autorizado",
        f"Sessão: {session_id}",
        f"Autorizado em: {authorised_at}",
        "",
        "Nada foi alterado ainda. Isto é a lista do que o ZeroBirus pode fazer, e só o que",
        "está marcado com [x] foi autorizado. Remover é mover para a quarentena, e dá para",
        "desfazer (ver o LEIA-ME).",
        "",
    ]
    for title, members in plan.groups():
        lines.append(f"{title}:")
        for item in members:
            mark = "[x]" if item.id in approved else "[ ]"
            lines.append(f"  {mark} {item.description}  ({item.level.value}, {item.id})")
            lines.append(f"      Porquê: {item.why}")
            if item.sha256:
                lines.append(f"      SHA-256: {item.sha256}")
        lines.append("")
    if plan.not_plannable:
        lines.append("Achados que o ZeroBirus não vai tocar:")
        for n in plan.not_plannable:
            lines.append(f"  - {n.item}: {n.reason}")
        lines.append("")
    chosen = [i for i in plan.items if i.id in approved]
    lines.append(f"Itens autorizados: {len(chosen)} de {len(plan.items)}.")
    return "\n".join(lines) + "\n"


def plan_to_dict(plan: Plan, approved_ids: Iterable[str]) -> dict[str, object]:
    """The plan as JSON-ready data, for ``plan.json`` in the session folder."""
    approved = set(approved_ids)
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "items": [
            {
                "id": i.id,
                "action": i.action.value,
                "target": i.target,
                "params": dict(i.params),
                "level": i.level.value,
                "risk": i.risk.value if i.risk else None,
                "why": i.why,
                "finding_id": i.finding_id,
                "sha256": i.sha256,
                "default_selected": i.default_selected,
                "approved": i.id in approved,
            }
            for i in plan.items
        ],
        "not_plannable": [
            {"finding_id": n.finding_id, "item": n.item, "reason": n.reason}
            for n in plan.not_plannable
        ],
        "digest_of_approved": digest(i for i in plan.items if i.id in approved),
    }
