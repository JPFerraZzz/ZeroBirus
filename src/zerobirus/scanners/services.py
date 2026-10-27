"""Services. Microsoft or not is decided by signature and path, never by name."""

from __future__ import annotations

from zerobirus.core.heuristics import (
    extract_executable,
    location_kind,
    random_component,
    runs_a_shell,
)
from zerobirus.core.models import CheckResult, Finding, Level, ServiceInfo, Signature
from zerobirus.core.rules import Rules, load_rules
from zerobirus.core.safety import SystemContext, is_protected_process, is_system_process_name
from zerobirus.platform.base import Inspector
from zerobirus.scanners.common import (
    command_signals,
    finish,
    is_microsoft_signed,
    lookup,
    make_finding,
    merge_gaps,
    signature_map,
    signature_signals,
    under_any,
)

CHECK = "services"


def judge(
    svc: ServiceInfo, ctx: SystemContext, rules: Rules, sigs: dict[str, Signature]
) -> Finding | None:
    image = extract_executable(svc.image_command)
    sig = lookup(sigs, image)
    expected_home = [ctx.system_root, *ctx.program_files]
    if image and is_microsoft_signed(sig) and under_any(image, expected_home):
        return None

    signals = command_signals(svc.image_command, rules)
    if image and is_system_process_name(image.replace("/", "\\").rsplit("\\", 1)[-1]):
        name = image.replace("/", "\\").rsplit("\\", 1)[-1]
        if not is_protected_process(name, image, ctx):
            signals.append(rules.signal("system_name_wrong_location"))
    signals.append(rules.signal("service_non_microsoft"))
    if image and location_kind(image, ctx):
        signals.append(rules.signal("service_from_writable"))
        if random_component(image, ctx):
            signals.append(rules.signal("random_folder"))
    if runs_a_shell(svc.image_command):
        signals.append(rules.signal("shell_command"))
    signals += signature_signals(sig, rules)

    finding = make_finding(
        CHECK,
        svc.name,
        item=svc.display_name or svc.name,
        location=image or "(desconhecido)",
        rules=rules,
        signals=signals,
        evidence=(svc.image_command,),
        path=image,
        subject=(("kind", "service"), ("name", svc.name), ("image", image or "")),
        description=f"Serviço {svc.name} (arranque: {svc.start}).",
    )
    return finding if finding.level is not Level.OK else None


def scan(inspector: Inspector) -> CheckResult:
    rules = load_rules()
    ctx = inspector.system_context()
    observed = inspector.services()
    images = [i for s in observed.items if (i := extract_executable(s.image_command))]
    sigs, sig_gaps = signature_map(inspector, images)
    findings = [f for s in observed.items if (f := judge(s, ctx, rules, sigs)) is not None]
    return finish(CHECK, findings, [*merge_gaps(observed), *sig_gaps], len(observed.items))
