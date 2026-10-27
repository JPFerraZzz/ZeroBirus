"""``python -m zerobirus``: the same entry point as the ``zerobirus`` command."""

from zerobirus.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
