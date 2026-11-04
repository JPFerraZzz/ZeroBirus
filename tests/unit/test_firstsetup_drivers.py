"""FirstSetup (catalog, installer script) and AllDrivers (report rules)."""

from datetime import date

import pytest

from zerobirus.core.allup import PACKAGE_ID
from zerobirus.core.bigdiag import Status
from zerobirus.core.drivers import (
    AMD_PAGE,
    INTEL_PAGE,
    LINKS,
    NVIDIA_PAGE,
    OPTIONAL_UPDATES,
    installed_section,
    is_allowed_link,
    pending_section,
    vendor_links,
)
from zerobirus.core.firstsetup import (
    APPS,
    BY_ID,
    CATEGORIES,
    by_category,
    render_script,
)
from zerobirus.platform.fake.drivers import demo_drivers

# The sixteen headings of the Ninite page, as read on 2026-10-29.
NINITE_CATEGORIES = [
    "Web Browsers",
    "Messaging",
    "Media",
    ".NET",
    "Java",
    "Imaging",
    "3D Printing",
    "Documents",
    "Security",
    "File Sharing",
    "Online Storage",
    "Other",
    "Utilities",
    "Compression",
    "VC++ Redistributables",
    "Developer Tools",
]


def test_categories_are_the_sixteen_of_ninite_in_order() -> None:
    assert list(CATEGORIES) == NINITE_CATEGORIES


def test_every_app_has_a_unique_safe_id_and_a_category_with_apps() -> None:
    assert len({a.id for a in APPS}) == len(APPS)
    for a in APPS:
        assert PACKAGE_ID.match(a.id), a.id
    for c in CATEGORIES:
        assert by_category(c), c


def test_ids_known_to_be_missing_from_winget_are_not_offered() -> None:
    gone = {"WhatsApp.WhatsApp", "MusicBee.MusicBee", "ArtifexSoftware.GhostScript"}
    assert not gone & set(BY_ID)


def test_the_script_is_ascii_crlf_branded_and_installs_then_checks_each_app() -> None:
    text = render_script(["Mozilla.Firefox", "VideoLAN.VLC"], version="1.2.3")
    text.encode("ascii")
    assert "\r\n" in text
    assert text.count("\n") == text.count("\r\n")
    assert "ZeroBirus 1.2.3 - FirstSetup - by Ferraz" in text
    assert "install --id Mozilla.Firefox --exact --silent" in text
    assert "list --id Mozilla.Firefox --exact" in text  # the independent check
    assert text.index("Mozilla.Firefox") < text.index("VideoLAN.VLC")
    assert "[2/2] VLC" in text


def test_the_script_contains_nothing_cmd_would_give_a_meaning_to() -> None:
    every = render_script([a.id for a in APPS], version="x")
    lines = [ln for ln in every.split("\r\n") if ln.startswith("echo ")]
    for ln in lines:
        assert not any(c in ln[5:] for c in '|<>^%"!') or "%OK%" in ln or "%FAIL%" in ln, ln
    # The names printed inside the (...) blocks never carry parentheses of their own.
    for ln in every.split("\r\n"):
        if ln.startswith("if errorlevel"):
            assert (ln.count("("), ln.count(")")) == (2, 2), ln


@pytest.mark.parametrize("bad", ["--force", "Evil.Thing", "a&b", "", "Mozilla.Firefox & calc"])
def test_the_script_refuses_ids_outside_the_catalog(bad: str) -> None:
    with pytest.raises(ValueError, match="catalog"):
        render_script(["Mozilla.Firefox", bad], version="x")


def test_the_script_needs_at_least_one_app() -> None:
    with pytest.raises(ValueError, match="nothing"):
        render_script([], version="x")


# AllDrivers ------------------------------------------------------------------------------

TODAY = date(2026, 10, 29)


def test_old_drivers_get_attention_and_recent_ones_do_not() -> None:
    sec = installed_section(demo_drivers(), TODAY)
    by_label = {line.label: line for line in sec.lines}
    assert by_label["Placa gráfica de demonstração"].status is Status.OK
    assert by_label["Placa de rede de demonstração"].status is Status.ATENCAO
    assert "mais de 3 anos" in by_label["Placa de rede de demonstração"].value


def test_unread_parts_are_never_reported_as_fine() -> None:
    assert installed_section({}, TODAY).status is Status.NAO_LIDO
    assert pending_section({}).status is Status.NAO_LIDO
    assert pending_section({"pending": []}).status is Status.OK
    assert pending_section(demo_drivers()).status is Status.ATENCAO


def test_a_single_driver_as_an_object_is_accepted() -> None:
    raw = {"installed": demo_drivers()["installed"][0], "pending": {"title": "x"}}
    assert len(installed_section(raw, TODAY).lines) == 1
    assert len(pending_section(raw).lines) == 1


def test_vendor_pages_follow_the_graphics_maker() -> None:
    assert vendor_links(demo_drivers()) == [NVIDIA_PAGE]
    amd = {"installed": [{"class": "DISPLAY", "manufacturer": "Advanced Micro Devices, Inc."}]}
    assert vendor_links(amd) == [AMD_PAGE]
    intel = {"installed": [{"class": "DISPLAY", "manufacturer": "Intel Corporation"}]}
    assert vendor_links(intel) == [INTEL_PAGE]
    net = {"installed": [{"class": "NET", "manufacturer": "Intel Corporation"}]}
    assert vendor_links(net) == []  # only the graphics card gets a manufacturer page


def test_only_the_listed_links_can_be_opened() -> None:
    assert is_allowed_link(OPTIONAL_UPDATES)
    assert all(is_allowed_link(u) for u in LINKS)
    for bad in ("calc.exe", "file:///C:/Windows/System32/cmd.exe", "https://evil.example/", ""):
        assert not is_allowed_link(bad)
