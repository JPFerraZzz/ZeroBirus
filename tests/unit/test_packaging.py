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
    assert spec.count("uac_admin=True") == 2  # both executables ask for administrator
    assert "console=False" in spec  # the window opens without a console
    assert 'name="zerobirus-cli"' in spec
    assert "exclude_binaries=True" in spec  # onedir, not onefile
    assert "COLLECT(" in spec


def test_icon_is_a_valid_multi_size_ico_made_from_the_logo() -> None:
    import struct

    data = (PACKAGING / "zerobirus.ico").read_bytes()
    reserved, kind, count = struct.unpack_from("<HHH", data)
    assert (reserved, kind, count) == (0, 1, 7)
    sizes: list[int] = []
    for i in range(count):
        w, _h, _c, _r, planes, bpp, size, offset = struct.unpack_from("<BBBBHHII", data, 6 + 16 * i)
        sizes.append(w or 256)
        assert (planes, bpp) == (1, 32)
        assert data[offset : offset + 8] == b"\x89PNG\r\n\x1a\n"
        assert offset + size <= len(data)
    assert sizes == [16, 24, 32, 48, 64, 128, 256]


def test_logo_is_original_flat_and_uses_only_theme_colours() -> None:
    from zerobirus.ui.theme import TOKENS

    svg = (PACKAGING.parent / "src" / "zerobirus" / "ui" / "assets" / "logo.svg").read_text("utf-8")
    low = svg.lower()
    for banned in ("gradient", "filter", "shadow", "<text", "<image", "opacity"):
        assert banned not in low
    colours = set(__import__("re").findall(r"#[0-9a-fA-F]{6}", svg))
    assert {c.upper() for c in colours} <= {TOKENS.ink.upper(), TOKENS.accent.upper()}
