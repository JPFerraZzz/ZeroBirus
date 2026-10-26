# PyInstaller spec: --onedir build with the window (ZeroBirus.exe) and the console tool
# (zerobirus-cli.exe), administrator manifest, Ferraz version resource, own icon.
# Build (from the repository root, on Windows):
#   uv run python packaging/make_version_info.py packaging/version_info.txt
#   uv run pyinstaller --noconfirm --distpath dist --workpath build packaging/zerobirus.spec
import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

here = SPECPATH  # noqa: F821 - provided by PyInstaller
root = os.path.abspath(os.path.join(here, ".."))

hidden = collect_submodules("zerobirus.platform.windows") + ["psutil", "PySide6.QtSvg", "PySide6.QtSvgWidgets"]
datas = collect_data_files("zerobirus")  # rules/*.json, fake fixtures, scripts/*.ps1, logo.svg

a = Analysis(  # noqa: F821
    [os.path.join(here, "entry.py")],
    pathex=[os.path.join(root, "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "pydoc_data", "test"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
icon = os.path.join(here, "zerobirus.ico")
version = os.path.join(here, "version_info.txt")
# The window: no console, so double-clicking never opens a black box.
gui = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ZeroBirus",
    debug=False,
    strip=False,
    upx=False,
    console=False,
    uac_admin=True,
    icon=icon,
    version=version,
)
# The console tool: prints to the terminal (version, selftest, scan --json, screenshots).
cli = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="zerobirus-cli",
    debug=False,
    strip=False,
    upx=False,
    console=True,
    uac_admin=True,
    icon=icon,
    version=version,
)
coll = COLLECT(  # noqa: F821
    gui,
    cli,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="ZeroBirus",
)
