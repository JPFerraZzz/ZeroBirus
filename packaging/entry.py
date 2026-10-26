"""PyInstaller entry point. Kept outside the package so the frozen app starts the same way as
``python -m zerobirus``."""

from zerobirus.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
