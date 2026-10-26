import subprocess
import sys
from pathlib import Path

from PySide6.QtGui import QImage

from zerobirus.ui.screenshots import capture


def test_capture_at_100_percent_writes_every_stage_at_1280x720(tmp_path: Path) -> None:
    files = capture(tmp_path, scale=1.0, fixture="clean_pc")
    assert [f.name.split("-", 2)[2] for f in files] == [
        "1-context.png",
        "2-verify.png",
        "3-diagnosis.png",
        "4-diagnosis-threat.png",
        "5-authorize.png",
        "6-authorize-end.png",
    ]
    for f in files:
        image = QImage(str(f))
        assert (image.width(), image.height()) == (1280, 720)


def test_capture_at_150_percent_really_scales_in_its_own_process(tmp_path: Path) -> None:
    """Qt reads QT_SCALE_FACTOR once, so the 150% shot must come from a fresh process."""
    done = subprocess.run(  # noqa: S603 - our own interpreter, no shell
        [
            sys.executable,
            "-m",
            "zerobirus",
            "screenshots",
            "--out",
            str(tmp_path),
            "--scale",
            "1.5",
            "--fixture",
            "clean_pc",
        ],
        check=False,
        capture_output=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    files = sorted(tmp_path.glob("clean_pc-150pct-*.png"))
    assert len(files) == 6
    for f in files:
        image = QImage(str(f))
        assert (image.width(), image.height()) == (1280, 720)  # physical pixels
