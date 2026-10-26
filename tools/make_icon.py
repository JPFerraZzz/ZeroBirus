"""Generate packaging/zerobirus.ico from src/zerobirus/ui/assets/logo.svg.

    uv run python tools/make_icon.py

Sizes 16, 24, 32, 48, 64, 128 and 256, each stored as PNG inside the ICO container (supported
by Windows Vista and later). Needs Qt's SVG renderer, which ships with PySide6.
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

REPO = Path(__file__).resolve().parents[1]
SIZES = (16, 24, 32, 48, 64, 128, 256)


def render_png(svg: Path, size: int) -> bytes:
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice
    from PySide6.QtGui import QColor, QGuiApplication, QImage, QPainter
    from PySide6.QtSvg import QSvgRenderer

    app = QGuiApplication.instance() or QGuiApplication(["make_icon"])
    _ = app
    renderer = QSvgRenderer(str(svg))
    if not renderer.isValid():
        raise SystemExit(f"cannot read {svg}")
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(QColor(0, 0, 0, 0))
    painter = QPainter(image)
    renderer.render(painter)
    painter.end()
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    image.save(buffer, "PNG")
    return bytes(data.data())


def build_ico(pngs: list[tuple[int, bytes]]) -> bytes:
    header = struct.pack("<HHH", 0, 1, len(pngs))
    offset = 6 + 16 * len(pngs)
    entries = b""
    body = b""
    for size, png in pngs:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset + len(body))
        body += png
    return header + entries + body


def main() -> int:
    svg = REPO / "src" / "zerobirus" / "ui" / "assets" / "logo.svg"
    out = REPO / "packaging" / "zerobirus.ico"
    out.write_bytes(build_ico([(s, render_png(svg, s)) for s in SIZES]))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
