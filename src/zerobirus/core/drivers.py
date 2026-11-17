"""AllDrivers: which drivers are installed, and what Windows Update offers (PitStop, D-016).

Pure data and rules. ZeroBirus never downloads or installs a driver: it lists what the PC has
(version and date), asks Windows Update what it has pending, and opens the right page so the
Windows does the update. Only the links in ``LINKS`` can ever be opened.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from typing import Any

from zerobirus.core.bigdiag import Line, Section, Status
from zerobirus.core.bigdiag import _list as as_list  # pyright: ignore[reportPrivateUsage]

OPTIONAL_UPDATES = "ms-settings:windowsupdate-optionalupdates"
NVIDIA_PAGE = "https://www.nvidia.com/Download/index.aspx"
AMD_PAGE = "https://www.amd.com/en/support/download/drivers.html"
INTEL_PAGE = "https://www.intel.com/content/www/us/en/download-center/home.html"
LINKS: dict[str, str] = {
    OPTIONAL_UPDATES: "Atualizações opcionais do Windows",
    NVIDIA_PAGE: "Página de drivers da NVIDIA",
    AMD_PAGE: "Página de drivers da AMD",
    INTEL_PAGE: "Centro de downloads da Intel",
}
VENDOR_PAGES = {
    "nvidia": NVIDIA_PAGE,
    "advanced micro devices": AMD_PAGE,
    "amd": AMD_PAGE,
    "intel": INTEL_PAGE,
}
OLD_AFTER_DAYS = 3 * 365


def is_allowed_link(uri: str) -> bool:
    return uri in LINKS


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _age_days(iso: str, today: date) -> int | None:
    try:
        return (today - date.fromisoformat(iso[:10])).days
    except ValueError:
        return None


def installed_section(raw: Mapping[str, Any], today: date) -> Section:
    rows = as_list(raw.get("installed"))
    if not rows:
        return Section(
            "Drivers instalados", (Line("drivers", "não foi possível ler", Status.NAO_LIDO),)
        )
    lines: list[Line] = []
    for r in rows:
        name = _text(r.get("name")) or "Dispositivo sem nome"
        version, when = _text(r.get("version")) or "?", _text(r.get("date"))[:10] or "?"
        age = _age_days(when, today)
        old = age is not None and age > OLD_AFTER_DAYS
        lines.append(
            Line(
                name,
                f"versão {version} de {when}" + (" (com mais de 3 anos)" if old else ""),
                Status.ATENCAO if old else Status.OK,
            )
        )
    return Section(
        "Drivers instalados",
        tuple(lines),
        note="A data é a do driver, não a da instalação. Um driver antigo pode estar certo.",
    )


def pending_section(raw: Mapping[str, Any]) -> Section:
    pending = raw.get("pending")
    if pending is None:
        return Section(
            "Drivers que o Windows Update tem",
            (Line("Windows Update", "não foi possível perguntar", Status.NAO_LIDO),),
        )
    rows = as_list(pending)
    if not rows:
        return Section(
            "Drivers que o Windows Update tem",
            (Line("Windows Update", "não tem drivers novos para este PC"),),
        )
    return Section(
        "Drivers que o Windows Update tem",
        tuple(Line(_text(r.get("title")) or "Driver", "disponível", Status.ATENCAO) for r in rows),
        note="Instala-os em «Atualizações opcionais» do Windows: é o Windows que os instala.",
    )


def vendor_links(raw: Mapping[str, Any]) -> list[str]:
    """The manufacturer pages for the graphics card(s), from the maker named by the driver."""
    found: list[str] = []
    for r in as_list(raw.get("installed")):
        if _text(r.get("class")).lower() != "display":
            continue
        maker = _text(r.get("manufacturer")).lower()
        for key, url in VENDOR_PAGES.items():
            if key in maker and url not in found:
                found.append(url)
    return found
