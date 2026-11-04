"""FirstSetup: pick the usual apps, get one installer script on the Desktop (PitStop, D-016/D-021).

Pure data and rules, no network and no OS access. The categories are the ones the Ninite page
shows (checked on 2026-10-29); the apps are the ones that have a winget package, by exact
package id. The generated script asks the Windows package manager to download and install, so
ZeroBirus itself never touches the network. Everything that goes into the script is checked
first: ids against a strict pattern, names against a short list of safe characters.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from zerobirus.core.allup import PACKAGE_ID

SCRIPT_NAME = "ZeroBirus-FirstSetup.cmd"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9 ._()+#-]{1,60}$")  # nothing cmd.exe gives a meaning to


@dataclass(frozen=True, slots=True)
class App:
    category: str
    name: str
    id: str
    verified: bool = True  # the id was found in the public winget-pkgs repository


def _apps(category: str, rows: Iterable[tuple[str, ...] | tuple[str, str, bool]]) -> list[App]:
    return [App(category, str(r[0]), str(r[1]), len(r) < 3 or bool(r[2])) for r in rows]


Q = False  # id not checked yet (the check was cut by the GitHub rate limit)

_ROWS: dict[str, list[App]] = {
    "Web Browsers": _apps(
        "Web Browsers",
        [
            ("Chrome", "Google.Chrome"),
            ("Opera", "Opera.Opera"),
            ("Firefox", "Mozilla.Firefox"),
            ("Edge", "Microsoft.Edge"),
            ("Brave", "Brave.Brave"),
            ("Vivaldi", "Vivaldi.Vivaldi"),
        ],
    ),
    "Messaging": _apps(
        "Messaging",
        [
            ("Zoom", "Zoom.Zoom"),
            ("Discord", "Discord.Discord"),
            ("Teams", "Microsoft.Teams"),
            ("Slack", "SlackTechnologies.Slack"),
            ("Telegram", "Telegram.TelegramDesktop"),
            ("Pidgin", "Pidgin.Pidgin"),
            ("Thunderbird", "Mozilla.Thunderbird"),
        ],
    ),
    "Media": _apps(
        "Media",
        [
            ("iTunes", "Apple.iTunes"),
            ("VLC", "VideoLAN.VLC"),
            ("AIMP", "AIMP.AIMP"),
            ("foobar2000", "PeterPawlowski.foobar2000"),
            ("Audacity", "Audacity.Audacity"),
            ("K-Lite Codecs", "CodecGuide.K-LiteCodecPack.Standard"),
            ("Spotify", "Spotify.Spotify"),
            ("HandBrake", "HandBrake.HandBrake"),
            ("OBS Studio", "OBSProject.OBSStudio"),
        ],
    ),
    ".NET": _apps(
        ".NET",
        [
            (".NET Desktop Runtime 8", "Microsoft.DotNet.DesktopRuntime.8"),
            (".NET Desktop Runtime 9", "Microsoft.DotNet.DesktopRuntime.9"),
            (".NET Desktop Runtime 10", "Microsoft.DotNet.DesktopRuntime.10", Q),
            ("ASP.NET Core Runtime 8", "Microsoft.DotNet.AspNetCore.8"),
            ("ASP.NET Core Runtime 9", "Microsoft.DotNet.AspNetCore.9", Q),
        ],
    ),
    "Java": _apps(
        "Java",
        [
            ("Java JRE (Temurin) 8", "EclipseAdoptium.Temurin.8.JRE"),
            ("JDK (Temurin) 17", "EclipseAdoptium.Temurin.17.JDK"),
            ("JDK (Temurin) 21", "EclipseAdoptium.Temurin.21.JDK"),
        ],
    ),
    "Imaging": _apps(
        "Imaging",
        [
            ("Krita", "KDE.Krita"),
            ("Blender", "BlenderFoundation.Blender"),
            ("Paint.NET", "dotPDN.PaintDotNet"),
            ("GIMP", "GIMP.GIMP"),
            ("IrfanView", "IrfanSkiljan.IrfanView"),
            ("XnView", "XnSoft.XnViewMP"),
            ("Inkscape", "Inkscape.Inkscape"),
            ("Greenshot", "Greenshot.Greenshot"),
            ("ShareX", "ShareX.ShareX"),
        ],
    ),
    "3D Printing": _apps("3D Printing", [("UltiMaker Cura", "Ultimaker.Cura")]),
    "Documents": _apps(
        "Documents",
        [
            ("Foxit Reader", "Foxit.FoxitReader"),
            ("LibreOffice", "TheDocumentFoundation.LibreOffice"),
            ("SumatraPDF", "SumatraPDF.SumatraPDF"),
            ("OpenOffice", "Apache.OpenOffice"),
        ],
    ),
    "Security": _apps("Security", [("Malwarebytes", "Malwarebytes.Malwarebytes")]),
    "File Sharing": _apps("File Sharing", [("qBittorrent", "qBittorrent.qBittorrent")]),
    "Online Storage": _apps(
        "Online Storage",
        [
            ("Dropbox", "Dropbox.Dropbox"),
            ("Google Drive for Desktop", "Google.GoogleDrive"),
            ("OneDrive", "Microsoft.OneDrive"),
        ],
    ),
    "Other": _apps(
        "Other",
        [
            ("Steam", "Valve.Steam"),
            ("Epic Games Launcher", "EpicGames.EpicGamesLauncher"),
            ("KeePass 2", "DominikReichl.KeePass"),
            ("KeePassXC", "KeePassXCTeam.KeePassXC"),
            ("1Password", "AgileBits.1Password"),
            ("Bitwarden", "Bitwarden.Bitwarden"),
            ("Everything", "voidtools.Everything"),
            ("NVDA", "NVAccess.NVDA"),
            ("Claude", "Anthropic.Claude", Q),
            ("ChatGPT", "OpenAI.ChatGPT", Q),
        ],
    ),
    "Utilities": _apps(
        "Utilities",
        [
            ("Wireshark", "WiresharkFoundation.Wireshark", Q),
            ("PowerToys", "Microsoft.PowerToys", Q),
            ("AnyDesk", "AnyDeskSoftwareGmbH.AnyDesk", Q),
            ("TeamViewer", "TeamViewer.TeamViewer", Q),
            ("RustDesk", "RustDesk.RustDesk", Q),
            ("Tailscale", "tailscale.tailscale", Q),
            ("WireGuard", "WireGuard.WireGuard", Q),
            ("TeraCopy", "CodeSector.TeraCopy", Q),
            ("WizTree", "AntibodySoftware.WizTree", Q),
            ("WinDirStat", "WinDirStat.WinDirStat", Q),
            ("CCleaner", "Piriform.CCleaner", Q),
        ],
    ),
    "Compression": _apps(
        "Compression",
        [
            ("7-Zip", "7zip.7zip", Q),
            ("PeaZip", "PeaZip.PeaZip", Q),
            ("WinRAR", "RARLab.WinRAR", Q),
        ],
    ),
    "VC++ Redistributables": _apps(
        "VC++ Redistributables",
        [
            ("VC Redist x64 2015+", "Microsoft.VCRedist.2015+.x64", Q),
            ("VC Redist x86 2015+", "Microsoft.VCRedist.2015+.x86", Q),
            ("VC Redist x64 2013", "Microsoft.VCRedist.2013.x64", Q),
            ("VC Redist x86 2013", "Microsoft.VCRedist.2013.x86", Q),
        ],
    ),
    "Developer Tools": _apps(
        "Developer Tools",
        [
            ("Python 3", "Python.Python.3.13", Q),
            ("Git", "Git.Git", Q),
            ("GitHub Desktop", "GitHub.GitHubDesktop", Q),
            ("Docker Desktop", "Docker.DockerDesktop", Q),
            ("Node.js", "OpenJS.NodeJS", Q),
            ("FileZilla", "TimKosse.FileZilla.Client", Q),
            ("Notepad++", "Notepad++.Notepad++", Q),
            ("Sublime Text 4", "SublimeHQ.SublimeText.4", Q),
            ("WinSCP", "WinSCP.WinSCP", Q),
            ("PuTTY", "PuTTY.PuTTY", Q),
            ("WinMerge", "WinMerge.WinMerge", Q),
            ("Visual Studio Code", "Microsoft.VisualStudioCode", Q),
            ("Cursor", "Anysphere.Cursor", Q),
        ],
    ),
}
CATEGORIES: tuple[str, ...] = tuple(_ROWS)
APPS: tuple[App, ...] = tuple(a for rows in _ROWS.values() for a in rows)
BY_ID: dict[str, App] = {a.id: a for a in APPS}
SECURITY_NOTE = (
    "Instala só um antivírus. O Windows já traz o Microsoft Defender; um segundo antivírus põe o "
    "Defender em modo passivo."
)


def by_category(category: str) -> list[App]:
    return list(_ROWS[category])


def _ascii(text: str) -> str:
    """Plain ASCII without parentheses: those would close the block they are echoed in."""
    plain = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    return plain.replace("(", "").replace(")", "")


def render_script(ids: Iterable[str], *, version: str) -> str:
    """The installer script (CRLF, plain ASCII). Raises ValueError for anything not in the
    catalog or not safe to put in a command line: ids and names are checked, never trusted."""
    chosen: list[App] = []
    for package_id in dict.fromkeys(ids):
        app = BY_ID.get(package_id)
        if app is None or not PACKAGE_ID.match(app.id) or not _SAFE_NAME.match(app.name):
            raise ValueError(f"not an app of the catalog: {package_id!r}")
        chosen.append(app)
    if not chosen:
        raise ValueError("nothing was chosen")
    n = len(chosen)
    out = [
        "@echo off",
        "setlocal",
        "title ZeroBirus FirstSetup - by Ferraz",
        "echo ============================================================",
        f"echo   ZeroBirus {version} - FirstSetup - by Ferraz",
        "echo ============================================================",
        f"echo Vai instalar {n} aplicacoes com o winget, o gestor de pacotes do Windows.",
        "echo O ZeroBirus nao descarrega nada: quem descarrega e o Windows.",
        "echo.",
        'set "WINGET=%LOCALAPPDATA%\\Microsoft\\WindowsApps\\winget.exe"',
        'if not exist "%WINGET%" (',
        "  echo O winget nao esta instalado neste PC. Instala o App Installer da Microsoft.",
        "  pause",
        "  exit /b 1",
        ")",
        "set OK=0",
        "set FAIL=0",
    ]
    for i, app in enumerate(chosen, start=1):
        pid = app.id
        out += [
            f"echo [{i}/{n}] {_ascii(app.name)}",
            f'"%WINGET%" install --id {pid} --exact --silent --accept-package-agreements '
            "--accept-source-agreements --disable-interactivity",
            # Independent check: the package must now be in the installed list.
            f'"%WINGET%" list --id {pid} --exact --accept-source-agreements >nul 2>&1',
            f"if errorlevel 1 (set /a FAIL+=1 & echo   NAO CONFIRMADA: {_ascii(app.name)}) "
            f"else (set /a OK+=1 & echo   CONFIRMADA: {_ascii(app.name)})",
        ]
    out += [
        "echo.",
        "echo Confirmadas: %OK%   Nao confirmadas: %FAIL%",
        "echo Uma aplicacao pode ja estar instalada, precisar de reiniciar ou nao existir.",
        "pause",
    ]
    text = "\r\n".join(out) + "\r\n"
    text.encode("ascii")  # fails loudly if anything non-ASCII slipped in
    return text
