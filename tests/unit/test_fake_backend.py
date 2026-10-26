from zerobirus.cli import selftest
from zerobirus.platform.base import Inspector
from zerobirus.platform.fake import FakeInspector


def test_fake_inspector_satisfies_protocol() -> None:
    inspector: Inspector = FakeInspector()
    assert inspector.is_elevated()
    assert inspector.system_context().system_root == "C:\\Windows"
    assert {p.name for p in inspector.processes().items} >= {"System", "svchost.exe"}


def test_selftest_passes_on_clean_fixture() -> None:
    assert selftest() == []
