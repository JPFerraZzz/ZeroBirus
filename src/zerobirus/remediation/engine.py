"""Stage 4: carry out an authorised plan, and nothing else (BRIEF section 5).

Every rule lives here, in code that runs and is tested on Linux:

- the only input is an ``AuthorizedPlan``; an item that is not in it, or that was altered
  after authorisation, is refused (``NotAuthorized``);
- every item is checked again against ``core.safety`` and against the live state (a PID reused
  by another program, a path that now goes through a junction, a key that is not an autorun
  key), whatever the interface said;
- order is fixed: restore point, undo information for everything, processes, persistence,
  files, Defender, hosts, firewall;
- removing a file or folder is moving it into the session's quarantine; permanent deletion
  exists only as ``delete_quarantined``, called on explicit request;
- a result is REMOVIDO or EM_QUARENTENA only after the backend re-reads the real state and
  confirms it.

Everything that comes from the system (names, paths, messages) is data: it is never run.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from zerobirus.core.models import ActionResult
from zerobirus.core.plan import EXCLUSION_KINDS, ActionType, AuthorizedPlan, PlanItem, item_id
from zerobirus.core.redact import redact
from zerobirus.core.safety import (
    SystemContext,
    is_protected_path,
    is_protected_process,
    normalize_windows_path,
)
from zerobirus.core.session import Session
from zerobirus.remediation.ops import SystemOps

UNDO_SCHEMA_VERSION = 1
QUARANTINE_DIR = "quarantine"

FILE_ACTIONS = frozenset(
    {
        ActionType.QUARANTINE_FILE,
        ActionType.QUARANTINE_FOLDER,
        ActionType.QUARANTINE_STARTUP_SHORTCUT,
        ActionType.CLEAN_TEMP_FILE,
        ActionType.CLEAN_TEMP_FOLDER,
    }
)
FOLDER_ACTIONS = frozenset({ActionType.QUARANTINE_FOLDER, ActionType.CLEAN_TEMP_FOLDER})

# Fixed order of stage 4 (step 3 processes, step 4 what brings them back, step 5 files, ...).
_ORDER: tuple[tuple[ActionType, ...], ...] = (
    (ActionType.KILL_PROCESS,),
    (ActionType.REMOVE_TASK,),
    (ActionType.DISABLE_SERVICE,),
    (ActionType.REMOVE_REGISTRY_VALUE,),
    (ActionType.QUARANTINE_STARTUP_SHORTCUT,),
    (ActionType.REMOVE_WMI_BINDING,),
    (
        ActionType.QUARANTINE_FILE,
        ActionType.QUARANTINE_FOLDER,
        ActionType.CLEAN_TEMP_FILE,
        ActionType.CLEAN_TEMP_FOLDER,
    ),
    (ActionType.REMOVE_DEFENDER_EXCLUSION,),
    (ActionType.REMOVE_HOSTS_LINE, ActionType.ADD_HOSTS_BLOCK),
    (ActionType.ADD_FIREWALL_BLOCK,),
)
_RANK = {a: i for i, group in enumerate(_ORDER) for a in group}

_AUTORUN_KEY = re.compile(
    r"^software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\"
    r"(?:run|runonce|policies\\explorer\\run)$",
    re.IGNORECASE,
)
_IFEO_KEY = re.compile(
    r"^software\\(?:wow6432node\\)?microsoft\\windows nt\\currentversion\\"
    r"image file execution options\\[^\\]+$",
    re.IGNORECASE,
)
_SERVICE_NAME = re.compile(r"^[\w .$@-]{1,256}$")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_NEVER_BLOCK_SUFFIXES = (
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "live.com",
    "office.com",
    "office365.com",
    "msftconnecttest.com",
    "google.com",
    "localhost",
)

HOSTS_MARK = "# ZeroBirus"

HELP_LOCKED = (
    "O ficheiro está em uso ou o Windows não deixou mexer nele. Termina o programa que o usa, "
    "ou reinicia o PC e repete. Se continuar, usa o Modo de Segurança ou a Análise offline "
    "do Microsoft Defender."
)


class NotAuthorized(Exception):
    """The item is not in the authorised plan (or the plan was altered after authorising)."""


class RestorePointFailed(Exception):
    """No restore point could be created; the caller decides whether to go on without one."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ItemResult:
    item_id: str
    action: ActionType
    target: str
    result: ActionResult
    detail: str


@dataclass(frozen=True, slots=True)
class UndoResult:
    item_id: str
    ok: bool
    detail: str


@dataclass(frozen=True, slots=True)
class Outcome:
    restore_point: str  # "criado", "ignorado" or the reason it failed
    results: tuple[ItemResult, ...]


@dataclass(frozen=True, slots=True)
class _Refusal:
    reason: str


class Remediation:
    def __init__(
        self,
        ops: SystemOps,
        ctx: SystemContext,
        session: Session,
        *,
        is_protected: Callable[[str], bool] | None = None,
        hosts_lines: Callable[[], list[str]] | None = None,
    ) -> None:
        self._ops = ops
        self._ctx = ctx
        self._session = session
        self._is_protected = is_protected or (lambda p: is_protected_path(p, ctx))
        self._hosts_lines = hosts_lines

    # public ---------------------------------------------------------------------------

    def run(self, plan: AuthorizedPlan, *, proceed_without_restore_point: bool = False) -> Outcome:
        if not plan.verify():
            raise NotAuthorized("o plano autorizado foi alterado depois de autorizado")
        restore = self._restore_point(plan, proceed_without_restore_point)
        items = sorted(plan.items, key=lambda i: _RANK.get(i.action, 99))
        results: dict[str, ItemResult] = {}

        # Step 2: undo information for everything, before anything changes.
        ready: list[PlanItem] = []
        for item in items:
            try:
                self.authorise_item(plan, item)
                refusal = self._gate(item)
                if refusal is not None:
                    results[item.id] = self._result(item, ActionResult.IGNORADO, refusal.reason)
                    continue
                self._save_record(item, self._capture(item), state="captured")
            except NotAuthorized as exc:
                results[item.id] = self._result(item, ActionResult.IGNORADO, str(exc))
                continue
            except Exception as exc:
                results[item.id] = self._result(
                    item,
                    ActionResult.FALHOU,
                    f"não foi possível guardar a informação para desfazer ({_why(exc)}); "
                    "por isso nada foi alterado neste item",
                )
                continue
            ready.append(item)

        failed_images: set[str] = set()
        for item in ready:
            result = self._apply(item, failed_images)
            results[item.id] = result
            self._finish_record(item, result)
            self._session.log(f"{item.id} {item.action.value} {result.result.value}")
        ordered = tuple(results[i.id] for i in items)
        self._session.write("results.json", [_result_dict(r) for r in ordered])
        return Outcome(restore, ordered)

    def authorise_item(self, plan: AuthorizedPlan, item: PlanItem) -> None:
        """Raise NotAuthorized unless this exact item is in the authorised plan."""
        if not plan.contains(item):
            raise NotAuthorized("este item não está no plano autorizado")
        if item.id != item_id(item.action, item.params):
            raise NotAuthorized("o identificador do item não corresponde ao seu conteúdo")

    def apply_item(self, plan: AuthorizedPlan, item: PlanItem) -> ItemResult:
        """Run a single item through every barrier. Used by tests and by retry in the UI."""
        self.authorise_item(plan, item)
        refusal = self._gate(item)
        if refusal is not None:
            return self._result(item, ActionResult.IGNORADO, refusal.reason)
        self._save_record(item, self._capture(item), state="captured")
        result = self._apply(item, set())
        self._finish_record(item, result)
        return result

    def undo_item(self, item_id_: str) -> UndoResult:
        try:
            record = self._load_record(item_id_)
        except (OSError, ValueError):
            return UndoResult(item_id_, False, "não há informação para desfazer este item")
        if record["state"] == "undone":
            return UndoResult(item_id_, True, "já estava desfeito")
        if record["state"] != "done":
            return UndoResult(item_id_, False, "este item não chegou a ser alterado")
        item = _item_from_record(record)
        if item is None:
            return UndoResult(item_id_, False, "o registo para desfazer está inválido")
        try:
            detail = self._undo(item, record)
        except Exception as exc:
            return UndoResult(item_id_, False, f"não foi possível desfazer: {_why(exc)}")
        record["state"] = "undone"
        self._write_record(item_id_, record)
        self._session.log(f"{item_id_} undone")
        return UndoResult(item_id_, True, detail)

    def undo_session(self) -> list[UndoResult]:
        out: list[UndoResult] = []
        for path in sorted(self._undo_dir().glob("*.json"), reverse=True):
            out.append(self.undo_item(path.stem))
        return out

    def delete_quarantined(self, item_ids: list[str]) -> list[UndoResult]:
        """Permanent deletion of already quarantined items. Only on explicit request."""
        out: list[UndoResult] = []
        base = (self._session.folder / QUARANTINE_DIR).resolve()
        for iid in item_ids:
            try:
                record = self._load_record(iid)
                dest = Path(record["undo"]["quarantined_to"]).resolve()
            except (OSError, ValueError, KeyError):
                out.append(UndoResult(iid, False, "este item não está na quarentena"))
                continue
            if record["state"] != "done" or dest.parent != base:
                out.append(UndoResult(iid, False, "este item não está na quarentena"))
                continue
            try:
                self._ops.delete_tree(str(dest))
                gone = self._ops.file_kind(str(dest)) == "missing"
            except OSError as exc:
                out.append(UndoResult(iid, False, f"não foi possível apagar: {_why(exc)}"))
                continue
            if gone:
                record["state"] = "deleted"
                self._write_record(iid, record)
                self._session.log(f"{iid} deleted from quarantine")
            out.append(UndoResult(iid, gone, "apagado da quarentena" if gone else "continua lá"))
        return out

    # restore point --------------------------------------------------------------------

    def _restore_point(self, plan: AuthorizedPlan, proceed: bool) -> str:
        reason = self._ops.create_restore_point(f"ZeroBirus {plan.session_id}")
        if reason is None:
            return "criado"
        if not proceed:
            raise RestorePointFailed(reason)
        self._session.log(f"restore point not created: {redact(reason)}")
        return f"não criado ({redact(reason)}), continuou com confirmação"

    # gate -----------------------------------------------------------------------------

    def _gate(self, item: PlanItem) -> _Refusal | None:
        a = item.action
        if a is ActionType.KILL_PROCESS:
            return self._gate_process(item)
        if a in FILE_ACTIONS or a is ActionType.QUARANTINE_FILE:
            return self._gate_file(item)
        if a is ActionType.REMOVE_REGISTRY_VALUE:
            return self._gate_registry(item)
        if a is ActionType.REMOVE_TASK:
            folder, name = item.param("folder"), item.param("name")
            if not name or not folder.startswith("\\") or not folder.endswith("\\"):
                return _Refusal("o nome ou a pasta da tarefa não são válidos")
            return None
        if a is ActionType.DISABLE_SERVICE:
            name, image = item.param("name"), item.param("image")
            if not _SERVICE_NAME.match(name):
                return _Refusal("o nome do serviço não é válido")
            if image and self._is_protected(image):
                return _Refusal("o ficheiro do serviço está num caminho protegido")
            return None
        if a is ActionType.REMOVE_WMI_BINDING:
            if not (item.param("filter") and item.param("consumer")):
                return _Refusal("faltam o filtro ou o consumidor da assinatura WMI")
            return None
        if a is ActionType.REMOVE_DEFENDER_EXCLUSION:
            if item.param("exclusion_kind") not in EXCLUSION_KINDS or not item.param("value"):
                return _Refusal("a exclusão do Defender não está bem identificada")
            return None
        if a is ActionType.REMOVE_HOSTS_LINE:
            return self._gate_hosts_line(item)
        if a is ActionType.ADD_HOSTS_BLOCK:
            host = item.param("host").lower()
            if not _HOSTNAME.match(host) or host.endswith(_NEVER_BLOCK_SUFFIXES):
                return _Refusal("este nome não pode ser bloqueado pelo ZeroBirus")
            return None
        if a is ActionType.ADD_FIREWALL_BLOCK:
            return self._gate_address(item.param("address"))
        return _Refusal("tipo de ação desconhecido")

    def _gate_process(self, item: PlanItem) -> _Refusal | None:
        pid = item.param("pid")
        if not pid.isdigit():
            return _Refusal("não há identificador do processo")
        image = self._ops.process_image(int(pid))
        if image is None:
            return _Refusal("o processo já tinha terminado")
        planned = item.param("path")
        if is_protected_process(
            item.param("name"), image or planned or None, self._ctx, pid=int(pid)
        ):
            return _Refusal("é um processo protegido do Windows ou da própria ferramenta")
        if not image:
            return _Refusal("não foi possível confirmar que programa é este processo")
        if planned and normalize_windows_path(image) != normalize_windows_path(planned):
            return _Refusal("o número do processo passou para outro programa; não foi tocado")
        return None

    def _gate_file(self, item: PlanItem) -> _Refusal | None:
        path = item.param("path")
        if not path:
            return _Refusal("não há caminho")
        if self._is_protected(path):
            return _Refusal("o caminho está protegido (Windows, pastas pessoais ou antivírus)")
        if self._within_quarantine(path):
            return _Refusal("o caminho é da própria quarentena")
        kind = self._ops.file_kind(path)
        if kind == "missing":
            return _Refusal("o ficheiro já não existe")
        if kind in ("link", "other"):
            return _Refusal("é um link, uma junção ou um ficheiro especial; não é seguido")
        if (kind == "dir") != (item.action in FOLDER_ACTIONS):
            return _Refusal("o tipo do caminho (ficheiro ou pasta) mudou desde a verificação")
        if not self._ops.resolves_to_itself(path):
            return _Refusal("o caminho passa por um link ou junção; não é seguido")
        if kind == "dir" and self._ops.tree_has_link(path):
            return _Refusal("a pasta contém links ou junções, ou não foi possível vê-la toda")
        return None

    def _within_quarantine(self, path: str) -> bool:
        base = normalize_windows_path(str(self._session.folder))
        n = normalize_windows_path(path)
        return n == base or n.startswith(base.rstrip("\\") + "\\")

    def _gate_registry(self, item: PlanItem) -> _Refusal | None:
        root, key, value = item.param("root"), item.param("key"), item.param("value")
        if root != "HKLM" and not root.startswith("HKU\\S-1-5-21-"):
            return _Refusal("a raiz do registo não é permitida")
        if _AUTORUN_KEY.match(key):
            return None if value else _Refusal("falta o nome do valor")
        if _IFEO_KEY.match(key) and value == "Debugger":
            return None
        return _Refusal("esta chave de registo não é de arranque: não é alterada")

    def _gate_hosts_line(self, item: PlanItem) -> _Refusal | None:
        line = item.param("line").strip()
        parts = line.split()
        if len(parts) < 2 or line.startswith("#"):
            return _Refusal("a linha não é uma entrada do ficheiro hosts")
        if any(p.lower() in ("localhost", "ip6-localhost") for p in parts[1:]):
            return _Refusal("as linhas de localhost não são tocadas")
        return None

    @staticmethod
    def _gate_address(text: str) -> _Refusal | None:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return _Refusal("o endereço não é um IP válido")
        if not ip.is_global:
            return _Refusal("só endereços públicos podem ser bloqueados")
        return None

    # execution ------------------------------------------------------------------------

    def _capture(self, item: PlanItem) -> dict[str, Any]:
        if item.action in FILE_ACTIONS:
            path = item.param("path")
            return {"original": path, "sha256": self._ops.fingerprint(path)}
        if item.action is ActionType.KILL_PROCESS:
            return {}  # a terminated process cannot be brought back
        return self._ops.capture(item)

    def _apply(self, item: PlanItem, failed_images: set[str]) -> ItemResult:
        try:
            if item.action in FILE_ACTIONS:
                return self._apply_file(item, failed_images)
            if item.action is ActionType.KILL_PROCESS:
                self._ops.terminate(int(item.param("pid")))
                if self._ops.verify(item):
                    return self._result(item, ActionResult.REMOVIDO, "O processo terminou.")
                if item.param("path"):
                    failed_images.add(normalize_windows_path(item.param("path")))
                return self._result(
                    item,
                    ActionResult.FALHOU,
                    "O processo continua a correr. Reinicia o PC e repete, ou usa o Modo de "
                    "Segurança.",
                )
            self._ops.perform(item)
            if self._ops.verify(item):
                return self._result(item, ActionResult.REMOVIDO, _DONE[item.action])
            return self._result(
                item,
                ActionResult.FALHOU,
                "Foi feito, mas a verificação independente não confirmou. Nada foi dado como "
                "feito.",
            )
        except Exception as exc:
            return self._result(item, ActionResult.FALHOU, f"{_why(exc)}. {_NEXT_STEP}")

    def _apply_file(self, item: PlanItem, failed_images: set[str]) -> ItemResult:
        path = item.param("path")
        if normalize_windows_path(path) in failed_images:
            return self._result(
                item,
                ActionResult.FALHOU,
                "O programa ainda está a correr, por isso o ficheiro não foi movido.",
            )
        before = self._ops.fingerprint(path)
        if before is None:
            return self._result(item, ActionResult.FALHOU, "Não foi possível ler o ficheiro.")
        dest = str(self._session.folder / QUARANTINE_DIR / f"{item.id}.quar")
        try:
            self._ops.move(path, dest)
        except PermissionError:
            return self._result(item, ActionResult.FALHOU, HELP_LOCKED)
        except OSError as exc:
            return self._result(item, ActionResult.FALHOU, f"{_why(exc)}. {HELP_LOCKED}")
        gone = self._ops.file_kind(path) == "missing"
        intact = self._ops.fingerprint(dest) == before
        if gone and intact:
            self._save_record(
                item,
                {"original": path, "sha256": before, "quarantined_to": dest},
                state="captured",
            )
            return self._result(
                item, ActionResult.EM_QUARENTENA, "Movido para a quarentena (dá para desfazer)."
            )
        return self._result(
            item,
            ActionResult.FALHOU,
            "A cópia na quarentena ou a remoção do original não foram confirmadas; "
            "o original foi deixado como estava quando possível.",
        )

    # undo -----------------------------------------------------------------------------

    def _undo(self, item: PlanItem, record: dict[str, Any]) -> str:
        saved: dict[str, Any] = record["undo"]
        if item.action in FILE_ACTIONS:
            original, dest = saved["original"], saved["quarantined_to"]
            if self._is_protected(original):
                raise RuntimeError("o local original está protegido")
            if self._ops.file_kind(dest) == "missing":
                raise RuntimeError("o ficheiro já não está na quarentena")
            if self._ops.file_kind(original) != "missing":
                raise RuntimeError("já existe outra coisa no local original; não foi substituída")
            self._ops.move(dest, original)
            if self._ops.fingerprint(original) != saved["sha256"]:
                raise RuntimeError("o conteúdo restaurado não coincide com o guardado")
            return "Restaurado para o local original."
        if item.action is ActionType.KILL_PROCESS:
            return "Um processo terminado não volta sozinho; abre o programa se precisares."
        self._ops.restore(item, saved)
        return "Restaurado."

    # records --------------------------------------------------------------------------

    def _undo_dir(self) -> Path:
        return self._session.undo_dir

    def _record_path(self, iid: str) -> Path:
        if not re.fullmatch(r"i-[0-9a-f]{12}", iid):
            raise ValueError("not an item id")
        return self._undo_dir() / f"{iid}.json"

    def _load_record(self, iid: str) -> dict[str, Any]:
        import json

        data = json.loads(self._record_path(iid).read_text("utf-8"))
        if not isinstance(data, dict) or data.get("schema_version") != UNDO_SCHEMA_VERSION:
            raise ValueError("unsupported undo record")
        return data

    def _write_record(self, iid: str, record: dict[str, Any]) -> None:
        from zerobirus.core.session import write_json_atomic

        write_json_atomic(self._record_path(iid), record)

    def _save_record(self, item: PlanItem, saved: dict[str, Any], *, state: str) -> None:
        self._write_record(
            item.id,
            {
                "schema_version": UNDO_SCHEMA_VERSION,
                "state": state,
                "item": {
                    "id": item.id,
                    "action": item.action.value,
                    "target": item.target,
                    "params": dict(item.params),
                },
                "undo": saved,
                "result": None,
            },
        )

    def _finish_record(self, item: PlanItem, result: ItemResult) -> None:
        record = self._load_record(item.id)
        record["result"] = result.result.value
        record["state"] = (
            "done"
            if result.result in (ActionResult.REMOVIDO, ActionResult.EM_QUARENTENA)
            else "failed"
        )
        self._write_record(item.id, record)

    @staticmethod
    def _result(item: PlanItem, result: ActionResult, detail: str) -> ItemResult:
        return ItemResult(item.id, item.action, item.target, result, redact(detail))


_NEXT_STEP = (
    "Passo seguinte: termina o programa em causa, reinicia o PC e repete; se continuar, "
    "usa o Modo de Segurança ou a Análise offline do Microsoft Defender."
)
_DONE = {
    ActionType.REMOVE_TASK: "Tarefa agendada removida (a definição ficou guardada).",
    ActionType.DISABLE_SERVICE: "Serviço parado e desativado.",
    ActionType.REMOVE_REGISTRY_VALUE: "Valor de registo removido (o original ficou guardado).",
    ActionType.REMOVE_WMI_BINDING: "Assinatura WMI removida (a definição ficou guardada).",
    ActionType.REMOVE_DEFENDER_EXCLUSION: "Exclusão do Defender removida.",
    ActionType.REMOVE_HOSTS_LINE: "Linha removida do ficheiro hosts (cópia guardada).",
    ActionType.ADD_HOSTS_BLOCK: "Nome bloqueado no ficheiro hosts.",
    ActionType.ADD_FIREWALL_BLOCK: "Endereço bloqueado na firewall.",
}


def _why(exc: BaseException) -> str:
    text = str(exc).strip() or type(exc).__name__
    return redact(text)[:300]


def _result_dict(r: ItemResult) -> dict[str, str]:
    return {
        "item_id": r.item_id,
        "action": r.action.value,
        "target": redact(r.target),
        "result": r.result.value,
        "detail": r.detail,
    }


def _item_from_record(record: dict[str, Any]) -> PlanItem | None:
    from zerobirus.core.models import Level

    try:
        raw = record["item"]
        action = ActionType(raw["action"])
        params = tuple(sorted((str(k), str(v)) for k, v in raw["params"].items()))
        if raw["id"] != item_id(action, params):
            return None
        return PlanItem(
            id=raw["id"],
            action=action,
            target=str(raw["target"]),
            params=params,
            level=Level.OK,
            why="",
            finding_id="",
            default_selected=False,
        )
    except (KeyError, ValueError, TypeError, AttributeError):
        return None
