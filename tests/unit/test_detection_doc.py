import subprocess
import sys
from pathlib import Path

from zerobirus.core.rules import load_rules

DOC = (Path(__file__).resolve().parents[2] / "docs" / "DETECTION.md").read_text("utf-8")


def test_every_signal_is_documented_with_its_weight() -> None:
    for code, rule in load_rules().signals.items():
        assert f"| `{code}` | {rule.weight} |" in DOC, code


def test_every_check_has_a_section() -> None:
    for title in (
        "Processos em execução",
        "Arranque com o Windows",
        "Tarefas agendadas",
        "Serviços",
        "Programas em pastas graváveis",
        "Ligações de rede",
        "Microsoft Defender",
        "Ficheiro hosts",
        "Assinaturas WMI",
    ):
        assert title in DOC


def test_the_generated_blocks_are_up_to_date() -> None:
    tool = Path(__file__).resolve().parents[2] / "tools" / "update_detection_doc.py"
    done = subprocess.run([sys.executable, str(tool), "--check"], check=False)  # noqa: S603
    assert done.returncode == 0, "run: uv run python tools/update_detection_doc.py"


def test_every_indicator_is_listed_with_its_status() -> None:
    for items in load_rules().indicators.values():
        for i in items:
            assert (
                f"| `{i.value}` | {'verificado' if i.verified else '**não verificado**'} |" in DOC
            )


def test_the_doc_states_the_unverified_rule() -> None:
    assert "nunca dá SUSPEITO sozinho" in DOC
    assert "2026-10-26" in DOC
    assert "https://attack.mitre.org/techniques/T1496/" in DOC
