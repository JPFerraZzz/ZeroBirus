"""Check the FirstSetup catalog against the public winget-pkgs repository (a dev tool, not the
product: ZeroBirus itself makes no network requests).

    uv run python tools/check_winget_ids.py            # only the ids still marked unverified
    GITHUB_TOKEN=... uv run python tools/check_winget_ids.py --all

The unauthenticated GitHub API allows 60 requests an hour; a token allows far more.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

from zerobirus.core.firstsetup import APPS


def exists(package_id: str) -> bool | None:
    parts = package_id.split(".")
    path = "/".join([package_id[0].lower(), *parts])
    url = f"https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/{path}"
    request = urllib.request.Request(url, headers={"User-Agent": "zerobirus-dev-check"})
    if token := os.environ.get("GITHUB_TOKEN"):
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30):  # noqa: S310
            return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        return None  # rate limited or another problem: not an answer
    except OSError:
        return None


def main() -> int:
    todo = [a for a in APPS if "--all" in sys.argv or not a.verified]
    missing = unknown = 0
    for app in todo:
        found = exists(app.id)
        word = {True: "EXISTE", False: "NAO EXISTE", None: "SEM RESPOSTA"}[found]
        print(f"{app.id}: {word}")
        missing += found is False
        unknown += found is None
    print(f"{len(todo)} verificados, {missing} inexistentes, {unknown} sem resposta.")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
