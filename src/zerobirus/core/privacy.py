"""Remove personal data from a report so it can be shared.

Redaction of secrets is ``core.redact``. This module is the other half: it replaces user
and machine names with stable placeholders and hides the content of personal folders. Both
apply to OUTPUT only; scoring always runs on the original strings.

Limits (also in docs/WINDOWS_TEST_PLAN.md): the computer name is replaced only where it
appears as the domain of an account; a name that appears inside an unrelated text is only
replaced if it is a known user name. Read the report before sharing it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from zerobirus.core.safety import SystemContext

SYSTEM_ACCOUNTS = frozenset(
    {
        "NT AUTHORITY",
        "NT SERVICE",
        "NT VIRTUAL MACHINE",
        "WINDOW MANAGER",
        "FONT DRIVER HOST",
        "BUILTIN",
        "IIS APPPOOL",
    }
)
BUILTIN_PROFILES = frozenset(
    {"public", "default", "default user", "all users", "defaultuser0", "defaultuser100000"}
)
OMITTED = "[omitido]"
MACHINE_PLACEHOLDER = "MAQUINA"
PERSONAL_SUBFOLDERS = ("Documents", "Desktop", "Pictures", "Videos", "Music", "OneDrive")

_USERS_IN_PATH = re.compile(r"(?i)\\users\\([^\\/\"'<>|*?\r\n]+)")
_ACCOUNT = re.compile(r"^([^\\/:]{1,64})\\([^\\/:]{1,64})$")


class Anonymizer:
    """Stable, deterministic placeholders for one report."""

    def __init__(self, ctx: SystemContext, strings: Iterable[str], accounts: Iterable[str]) -> None:
        names: dict[str, str] = {}

        def learn(name: str) -> None:
            key = name.strip().lower()
            if key and key not in BUILTIN_PROFILES and key not in names:
                names[key] = f"Utilizador{len(names) + 1}"

        for root in ctx.profile_roots:
            learn(root.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1])
        for text in strings:
            for m in _USERS_IN_PATH.finditer(text):
                learn(m.group(1))
        for account in accounts:
            parsed = _ACCOUNT.match(account)
            if parsed and parsed.group(1).upper() not in SYSTEM_ACCOUNTS:
                learn(parsed.group(2))
        self._names = names

        alternatives = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
        self._name_re = re.compile(rf"(?i)(?<!\w)({alternatives})(?!\w)") if names else None

        folders = list(ctx.personal_folders)
        for root in ctx.profile_roots:
            base = root.replace("/", "\\").rstrip("\\")
            folders += [f"{base}\\{sub}" for sub in PERSONAL_SUBFOLDERS]
        self._folders = [
            re.compile("(" + re.escape(f) + r")(\\[^\"<>|\r\n]*)?", re.IGNORECASE)
            for f in sorted(set(folders), key=len, reverse=True)
        ]

    def text(self, value: str) -> str:
        """Hide the content of personal folders and replace user names."""
        for pattern in self._folders:
            value = pattern.sub(
                lambda m: m.group(1) + (f"\\{OMITTED}" if m.group(2) else ""), value
            )
        if self._name_re is not None:
            value = self._name_re.sub(lambda m: self._names[m.group(1).lower()], value)
        return value

    def account(self, value: str) -> str:
        """``DOMAIN\\user`` to ``MAQUINA\\UtilizadorN``. System accounts are kept."""
        m = _ACCOUNT.match(value)
        if m is None:
            return self.text(value)
        domain, user = m.groups()
        if domain.upper() in SYSTEM_ACCOUNTS:
            return value
        return f"{MACHINE_PLACEHOLDER}\\{self._names.get(user.strip().lower(), user)}"
