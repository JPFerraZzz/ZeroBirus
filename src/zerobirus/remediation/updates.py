"""Run an authorised update plan, one package at a time, and check each one independently.

The only input is an ``UpdatePlan``. A package that is not in it, or a plan altered after it was
authorised, is refused. "Updated" is only claimed when a fresh listing no longer shows the
package: winget saying it worked is not enough (CLAUDE.md, independent verification).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from zerobirus.core.allup import PACKAGE_ID, UpdatePlan, UpdateResult, Upgrade
from zerobirus.platform.base import PackageUpdater


class NotAuthorized(Exception):
    """The plan was altered after it was authorised."""


def run_updates(
    plan: UpdatePlan,
    listed: Sequence[Upgrade],
    updater: PackageUpdater,
    *,
    should_stop: Callable[[], bool] = lambda: False,
    on_result: Callable[[UpdateResult], None] = lambda _r: None,
) -> tuple[UpdateResult, ...]:
    if not plan.verify():
        raise NotAuthorized("o plano autorizado foi alterado depois de autorizado")
    names = {u.id: u.name for u in listed}
    results: list[UpdateResult] = []

    def add(r: UpdateResult) -> None:
        results.append(r)
        on_result(r)

    for package_id in plan.ids:
        name = names.get(package_id, package_id)
        if should_stop():
            add(UpdateResult(package_id, name, False, "Não foi tentado: pararam antes."))
            continue
        if not plan.contains(package_id) or not PACKAGE_ID.match(package_id):
            add(UpdateResult(package_id, name, False, "Não está no plano autorizado."))
            continue
        try:
            ok, said = updater.upgrade(package_id)
            still = {u.id for u in updater.list_upgrades()}
        except Exception as exc:
            add(UpdateResult(package_id, name, False, f"Falhou: {str(exc)[:200]}"))
            continue
        if package_id not in still:
            add(UpdateResult(package_id, name, True, "Atualizada e confirmada na lista."))
        elif ok:
            add(
                UpdateResult(
                    package_id,
                    name,
                    False,
                    "O winget disse que correu bem, mas continua a aparecer com atualização. "
                    "Pode precisar de reiniciar ou de fechar o programa.",
                )
            )
        else:
            add(UpdateResult(package_id, name, False, f"Não foi atualizada: {said}"))
    return tuple(results)
