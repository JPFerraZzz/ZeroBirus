"""Turn the raw data a Windows backend collects into models. Pure, so it runs on Linux.

Everything here is data from the machine: nothing is executed, and anything missing or of
the wrong type becomes "unknown" (``None``), never a guess. The Windows backend only does
the I/O and hands the rows to these functions.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any, cast

from zerobirus.core.models import (
    DefenderState,
    Observed,
    Signature,
    SignatureStatus,
    TaskAction,
    TaskInfo,
    WmiBinding,
)
from zerobirus.core.rules import Rules, load_rules
from zerobirus.core.safety import SignerKind

_ISO = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")
_ORG = re.compile(r'(?:^|,\s*)O=(?:"([^"]*)"|([^,]*))', re.IGNORECASE)
_VAR = re.compile(r"%([^%]+)%")
# Authenticode status values of System.Management.Automation.SignatureStatus.
_VALID, _NOT_SIGNED, _HASH_MISMATCH, _NOT_TRUSTED = 0, 2, 3, 4
TASK_STATE_DISABLED = 1


def _s(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _seq(value: Any) -> list[Any]:
    return list(value)


def as_rows(value: Any) -> list[dict[str, Any]]:
    """A PowerShell result (one object or a list of them) as a list of dicts."""
    if isinstance(value, dict):
        return [dict(cast("dict[str, Any]", value))]
    if isinstance(value, list):
        return [dict(cast("dict[str, Any]", v)) for v in _seq(value) if isinstance(v, dict)]
    return []


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return _seq(value) if isinstance(value, list) else [value]


def organisation(subject: str) -> str:
    """The ``O=`` part of a certificate subject, or an empty string."""
    m = _ORG.search(subject)
    return ((m.group(1) or m.group(2) or "") if m else "").strip()


def classify_signer(subject: str, rules: Rules | None = None) -> SignerKind:
    """Who signed, from the certificate subject of a signature already known to be valid."""
    rules = rules or load_rules()
    org = organisation(subject).lower()
    if org and org in rules.microsoft_orgs:
        return SignerKind.MICROSOFT
    if org and any(vendor in org for vendor in rules.antivirus_orgs):
        return SignerKind.ANTIVIRUS_VENDOR
    return SignerKind.OTHER


def parse_signatures(raw: Any, rules: Rules | None = None) -> tuple[Signature, ...]:
    out: list[Signature] = []
    for row in as_rows(raw):
        path = _s(row.get("path"))
        status = row.get("status")
        subject = _s(row.get("subject"))
        if not path or not isinstance(status, int) or isinstance(status, bool):
            continue
        if status == _VALID:
            out.append(
                Signature(path, SignatureStatus.VALID, classify_signer(subject, rules), subject)
            )
        elif status == _NOT_SIGNED:
            out.append(Signature(path, SignatureStatus.UNSIGNED, SignerKind.UNSIGNED, ""))
        elif status in (_HASH_MISMATCH, _NOT_TRUSTED):
            out.append(Signature(path, SignatureStatus.INVALID, SignerKind.OTHER, subject))
        else:
            out.append(Signature(path, SignatureStatus.UNKNOWN, SignerKind.OTHER, subject))
    return tuple(out)


def iso_minutes(text: str | None) -> int | None:
    """``PT5M`` to 5. Only the repeat interval of a task trigger is expected here."""
    if not text:
        return None
    m = _ISO.match(text.strip().upper())
    if m is None or not any(m.groups()):
        return None
    days, hours, minutes, seconds = (int(g) if g else 0 for g in m.groups())
    total = days * 1440 + hours * 60 + minutes + (1 if seconds else 0)
    return total or None


def parse_tasks(raw: Any, *, elevated: bool) -> Observed[TaskInfo]:
    tasks: list[TaskInfo] = []
    for row in as_rows(raw):
        actions = tuple(
            TaskAction(_s(a.get("execute")), _s(a.get("arguments")))
            for a in as_rows(row.get("actions"))
            if _s(a.get("execute"))
        )
        state = row.get("state")
        tasks.append(
            TaskInfo(
                folder=_s(row.get("folder")),
                name=_s(row.get("name")),
                enabled=state != TASK_STATE_DISABLED,
                actions=actions,
                triggers=tuple(_s(t) for t in _list(row.get("triggers")) if _s(t)),
                repeat_minutes=iso_minutes(_s(row.get("repetition")) or None),
            )
        )
    gaps = () if elevated else ("sem administrador algumas tarefas agendadas não são legíveis",)
    return Observed(tuple(tasks), gaps)


def _opt_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _opt_list(value: Any, *, readable: bool) -> tuple[str, ...] | None:
    """A list from PowerShell. ``None`` (and "N/A: ..." markers) mean "could not be read"."""
    if not readable or value is None:
        return None
    items = [v for v in _list(value) if isinstance(v, str) and v.strip()]
    if any(v.upper().startswith("N/A:") for v in items):
        return None
    return tuple(items)


def parse_defender(raw: Any, *, elevated: bool) -> Observed[DefenderState]:
    rows = as_rows(raw)
    if not rows:
        return Observed[DefenderState]((), ("o Defender não devolveu dados",))
    row = rows[0]
    errors = {_s(e) for e in _list(row.get("errors"))}
    if {"status", "preference"} <= errors:
        return Observed[DefenderState](
            (), ("o Microsoft Defender não está disponível ou está desativado",)
        )
    age = row.get("sigage")
    mode = _s(row.get("amrunning")).lower()
    state = DefenderState(
        realtime=_opt_bool(row.get("realtime")),
        tamper_protection=_opt_bool(row.get("tamper")),
        passive_mode=("passive" in mode) if mode else None,
        signature_age_days=age if isinstance(age, int) and not isinstance(age, bool) else None,
        threats=_opt_list(row.get("threats"), readable=elevated),
        exclusion_paths=_opt_list(row.get("excl_paths"), readable=elevated),
        exclusion_extensions=_opt_list(row.get("excl_ext"), readable=elevated),
        exclusion_processes=_opt_list(row.get("excl_proc"), readable=elevated),
        exclusion_ips=_opt_list(row.get("excl_ip"), readable=elevated),
    )
    return Observed((state,))


def parse_wmi(raw: Any) -> tuple[WmiBinding, ...]:
    return tuple(
        WmiBinding(
            filter_name=_s(r.get("filter")),
            consumer_name=_s(r.get("consumer")),
            consumer_class=_s(r.get("consumer_class")),
            command=_s(r.get("command")),
        )
        for r in as_rows(raw)
    )


def parse_shortcuts(raw: Any) -> dict[str, str]:
    """Shortcut path to the command it runs (``"target" arguments``)."""
    out: dict[str, str] = {}
    for row in as_rows(raw):
        path, target, args = _s(row.get("path")), _s(row.get("target")), _s(row.get("arguments"))
        if path and target:
            out[path] = f'"{target}" {args}'.rstrip()
    return out


def expand_vars(value: str, variables: Mapping[str, str]) -> str:
    """Expand ``%NAME%`` from ``variables`` (case-insensitive). Unknown names stay as written."""
    lowered = {k.lower(): v for k, v in variables.items()}
    return _VAR.sub(lambda m: lowered.get(m.group(1).lower(), m.group(0)), value)


def profile_variables(profile_root: str) -> dict[str, str]:
    """Per-user environment variables of a profile, so another user's registry is read right."""
    base = profile_root.rstrip("\\")
    return {
        "USERPROFILE": base,
        "APPDATA": base + "\\AppData\\Roaming",
        "LOCALAPPDATA": base + "\\AppData\\Local",
        "TEMP": base + "\\AppData\\Local\\Temp",
        "TMP": base + "\\AppData\\Local\\Temp",
    }


def offline_profiles_gap(names: list[str]) -> str | None:
    """One grouped, calm line for the profiles whose registry hive is not loaded.

    Their Run keys cannot be read without mounting the hive, which would change the registry,
    so it is not done (offline hive reading is planned for v1.1). The check is therefore
    NAO_VERIFICADO, which is a statement of what was not looked at, not an alarm.
    """
    unique = sorted(dict.fromkeys(n for n in names if n), key=str.lower)
    if not unique:
        return None
    return f"persistência de utilizadores sem sessão iniciada: perfis {', '.join(unique)}"


def parse_ps_envelope(text: str) -> tuple[Any, list[str]]:
    """The JSON a bridge script prints: ``{"items": ..., "errors": [...]}``.

    Empty output is an empty result. Anything that is not that shape raises ``ValueError``.
    """
    stripped = text.strip()
    if not stripped:
        return [], []
    try:
        data: Any = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise ValueError("not JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("unexpected shape")
    fields = as_rows(data)[0]
    if "items" not in fields:
        raise ValueError("unexpected shape")
    errors = [e for e in _list(fields.get("errors")) if isinstance(e, str)]
    return fields["items"], errors
