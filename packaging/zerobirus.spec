# PyInstaller spec: --onedir build of the CLI, administrator manifest, Ferraz version resource.
# Build (from the repository root, on Windows):
#   uv run python packaging/make_version_info.py packaging/version_info.txt
#   uv run pyinstaller --noconfirm --distpath dist --workpath build packaging/zerobirus.spec
import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

here = SPECPATH  # noqa: F821 - provided by PyInstaller
root = os.path.abspath(os.path.join(here, ".."))

hidden = collect_submodules("zerobirus.platform.windows") + ["psutil"]
datas = collect_data_files("zerobirus")  # rules/*.json, fake fixtures, scripts/*.ps1

a = Analysis(  # noqa: F821
    [os.path.join(here, "entry.py")],
    pathex=[os.path.join(root, "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "pydoc_data", "test", "PySide6"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ZeroBirus",
    debug=False,
    strip=False,
    upx=False,
    console=True,
    uac_admin=True,
    version=os.path.join(here, "version_info.txt"),
)
coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="ZeroBirus",
)
