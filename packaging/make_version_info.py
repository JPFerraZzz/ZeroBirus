"""Write the Windows version resource for PyInstaller (``--version-file``).

    uv run python packaging/make_version_info.py packaging/version_info.txt

Manufacturer "Ferraz", description and version come from one place. Language is pt-PT.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zerobirus import __version__

COMPANY = "Ferraz"
PRODUCT = "ZeroBirus"
DESCRIPTION = "ZeroBirus by Ferraz: deteta e remove mineradores de criptomoeda e outro malware"
COPYRIGHT = "MIT License, Ferraz"
ORIGINAL_NAME = "ZeroBirus.exe"
LANG_PT_PT = 0x0816
UNICODE_CODEPAGE = 1200


def numeric_version(version: str) -> tuple[int, int, int, int]:
    parts = [int(p) for p in re.findall(r"\d+", version)[:4]]
    return (*parts, *([0] * (4 - len(parts))))  # type: ignore[return-value]


def render(version: str = __version__) -> str:
    v = numeric_version(version)
    table = f"{LANG_PT_PT:04X}{UNICODE_CODEPAGE:04X}"
    strings = {
        "CompanyName": COMPANY,
        "FileDescription": DESCRIPTION,
        "FileVersion": version,
        "InternalName": PRODUCT,
        "LegalCopyright": COPYRIGHT,
        "OriginalFilename": ORIGINAL_NAME,
        "ProductName": PRODUCT,
        "ProductVersion": version,
    }
    body = ",\n          ".join(f"StringStruct({k!r}, {val!r})" for k, val in strings.items())
    return f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={v},
    prodvers={v},
    mask=0x3F,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable({table!r}, [
          {body}
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [{LANG_PT_PT}, {UNICODE_CODEPAGE}])])
  ]
)
"""


def main(argv: list[str]) -> int:
    target = Path(argv[1] if len(argv) > 1 else "version_info.txt")
    target.write_text(render(), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
