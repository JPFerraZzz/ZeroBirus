import pytest
from ctx_factory import typical_context

from zerobirus.core.heuristics import (
    crack_word,
    extract_executable,
    is_writable_location,
    location_kind,
    looks_random,
    mentions_writable_env,
    paths_in_command,
    random_component,
    runs_a_shell,
)

CTX = typical_context()


@pytest.mark.parametrize(
    "name", ["kzqpx", "Qw3rTy", "a1b2c3d4", "xkcdfghjk", "9f8e7d6c5b4a", "bvnmkl"]
)
def test_random_looking_names(name: str) -> None:
    assert looks_random(name)


@pytest.mark.parametrize(
    "name",
    [
        "Discord",
        "Spotify",
        "Steam",
        "Python312",
        "Microsoft",
        "Google",
        "Slack",
        "Skype",
        "Temp",
        "OneDrive",
        "ccleaner",
        "TeamViewer",
        "x64",
        "Zoom",
        "Notepad++",
        "NVIDIA Corporation",
        "a",
    ],
)
def test_ordinary_names_do_not_look_random(name: str) -> None:
    assert not looks_random(name)


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        (r"C:\Users\Ana\AppData\Roaming\x\a.exe", "appdata"),
        (r"C:\Users\Ana\AppData\Local\x\a.exe", "appdata"),
        (r"C:\Users\Ana\AppData\Local\Temp\a.exe", "temp"),
        (r"C:\Users\Bob\AppData\Local\Temp\a.exe", "temp"),
        (r"C:\Users\Public\a.exe", "public"),
        (r"C:\Users\Ana\Downloads\a.exe", "downloads"),
        (r"C:\ProgramData\kzqpx\a.exe", "programdata"),
        (r"C:\Windows\Temp\a.exe", "windows_temp"),
        (r"C:\Program Files\App\a.exe", None),
        (r"C:\Windows\System32\a.exe", None),
        (r"C:\ProgramData\Microsoft\Windows Defender\Platform\a.exe", None),
        (r"D:\Perfis\Bob\AppData\Roaming\x\a.exe", None),
    ],
)
def test_location_kind(path: str, kind: str | None) -> None:
    assert location_kind(path, CTX) == kind
    assert is_writable_location(path, CTX) is (kind is not None)


def test_profile_outside_users_dir_is_known_through_profile_roots() -> None:
    ctx = typical_context(profile_roots=(r"C:\Users\Ana", r"D:\Perfis\Bob"))
    assert location_kind(r"D:\Perfis\Bob\AppData\Roaming\x\a.exe", ctx) == "appdata"


@pytest.mark.parametrize(
    ("path", "comp"),
    [
        (r"C:\Users\Ana\AppData\Roaming\kzqpx\x.exe", "kzqpx"),
        (r"C:\Users\Ana\AppData\Roaming\Discord\x.exe", None),
        (r"C:\Users\Ana\AppData\Roaming\Microsoft\kzqpx\x.exe", "kzqpx"),
        (r"C:\ProgramData\Qw3rTy\x.exe", "Qw3rTy"),
        (r"C:\Users\Public\kzqpx\x.exe", "kzqpx"),
        (r"C:\Users\Ana\AppData\Local\Temp\kzqpx\x.exe", "kzqpx"),
        (r"C:\Program Files\kzqpx\x.exe", None),
    ],
)
def test_random_component(path: str, comp: str | None) -> None:
    assert random_component(path, CTX) == comp


@pytest.mark.parametrize(
    ("command", "exe"),
    [
        (r'"C:\Program Files\App\app.exe" --x', r"C:\Program Files\App\app.exe"),
        (r"C:\Program Files\App\app.exe /silent", r"C:\Program Files\App\app.exe"),
        (r"C:\Windows\System32\svchost.exe -k netsvcs", r"C:\Windows\System32\svchost.exe"),
        (
            r"rundll32.exe C:\Users\Ana\AppData\Roaming\k\a.dll,Run",
            r"C:\Users\Ana\AppData\Roaming\k\a.dll",
        ),
        (r'"C:\Windows\System32\rundll32.exe" "C:\x\a.dll",Run', r"C:\x\a.dll"),
        ("", None),
        ("   ", None),
        ("miner.exe", "miner.exe"),
    ],
)
def test_extract_executable(command: str, exe: str | None) -> None:
    assert extract_executable(command) == exe


def test_paths_in_command_finds_payload_behind_a_shell() -> None:
    cmd = r"cmd.exe /c C:\Users\Ana\AppData\Roaming\kzqpx\a.exe -o stratum+tcp://p:3333"
    assert r"C:\Users\Ana\AppData\Roaming\kzqpx\a.exe" in paths_in_command(cmd)
    assert runs_a_shell(cmd)
    assert not runs_a_shell(r"C:\Windows\System32\svchost.exe -k x")


def test_writable_env_variables_are_noticed_unexpanded() -> None:
    assert mentions_writable_env(r"%APPDATA%\x\a.exe")
    assert mentions_writable_env(r"%TEMP%\a.exe")
    assert not mentions_writable_env(r"%SystemRoot%\system32\a.exe")


def test_crack_word() -> None:
    assert crack_word(r"C:\Users\Ana\Downloads\Photoshop CRACK\setup.exe") == "crack"
    assert crack_word(r"C:\Users\Ana\Downloads\setup.exe") is None
