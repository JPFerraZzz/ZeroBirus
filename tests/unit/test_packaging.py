import importlib.util
from pathlib import Path
from types import ModuleType

PACKAGING = Path(__file__).resolve().parents[2] / "packaging"


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "make_version_info", PACKAGING / "make_version_info.py"
    )
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_version_resource_names_ferraz_and_is_valid_python_for_pyinstaller() -> None:
    text = load().render("1.2.3")
    assert "StringStruct('CompanyName', 'Ferraz')" in text
    assert "filevers=(1, 2, 3, 0)" in text
    assert "'Translation', [2070, 1200]" in text
    assert "'081604B0'" in text
    compile(text, "version_info.txt", "eval")  # PyInstaller evaluates it as one expression


def test_numeric_version_pads_and_ignores_suffixes() -> None:
    mod = load()
    assert mod.numeric_version("0.0.0") == (0, 0, 0, 0)
    assert mod.numeric_version("1.2.3rc1") == (1, 2, 3, 1)
    assert mod.numeric_version("2.0") == (2, 0, 0, 0)


def test_spec_requests_the_administrator_manifest_and_onedir() -> None:
    spec = (PACKAGING / "zerobirus.spec").read_text("utf-8")
    assert "uac_admin=True" in spec
    assert "exclude_binaries=True" in spec  # onedir, not onefile
    assert "COLLECT(" in spec
