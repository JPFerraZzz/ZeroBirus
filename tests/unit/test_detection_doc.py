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


def test_indicator_sources_are_declared_unconfirmed() -> None:
    assert "Fontes: por confirmar" in DOC.replace("**", "")
