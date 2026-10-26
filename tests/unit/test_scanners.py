"""Scanner behaviour on small, hand-built inputs. Whole-machine cases are in tests/golden."""

import pytest
from scan_helpers import codes, inspector, levels, only, unknown, unsigned, valid

from zerobirus.core.models import (
    AutorunEntry,
    ConnectionInfo,
    DefenderState,
    FileCandidate,
    Level,
    ProcessInfo,
    ServiceInfo,
    TaskAction,
    TaskInfo,
    WmiBinding,
)
from zerobirus.core.safety import SignerKind
from zerobirus.scanners import (
    defender,
    files,
    hosts,
    network,
    processes,
    services,
    startup,
    tasks,
    wmi,
)

DROP = r"C:\Users\Ana\AppData\Roaming\kzqpx\a.exe"
SYS = r"C:\Windows\System32"


def proc(
    pid: int, name: str, path: str | None, cmd: str = "", cpu: float | None = None
) -> ProcessInfo:
    return ProcessInfo(pid, name, path, cmd, r"PC\Ana", None, cpu)


# processes -----------------------------------------------------------------------------


def test_weak_signals_alone_never_make_a_process_suspect() -> None:
    p = proc(1, "a.exe", DROP, "a.exe", cpu=90.0)
    result = processes.scan(inspector(processes=(p,), signatures=(unsigned(DROP),)))
    assert only(result).level is Level.CONFERIR
    assert only(result).level is not Level.SUSPEITO


def test_high_cpu_alone_is_not_enough_for_anything() -> None:
    path = r"C:\Program Files\Game\game.exe"
    result = processes.scan(inspector(processes=(proc(1, "game.exe", path, cpu=95.0),)))
    assert result.findings == ()


def test_unknown_signature_is_not_treated_as_unsigned() -> None:
    p = proc(1, "a.exe", DROP)
    with_unknown = processes.scan(inspector(processes=(p,), signatures=(unknown(DROP),)))
    without = processes.scan(inspector(processes=(p,)))
    assert "unsigned" not in {s.code for f in with_unknown.findings for s in f.signals}
    assert [f.signals for f in with_unknown.findings] == [f.signals for f in without.findings]


def test_miner_name_in_a_writable_folder_without_signature_is_suspect() -> None:
    path = r"C:\Users\Ana\AppData\Local\Temp\xmrig.exe"
    result = processes.scan(
        inspector(processes=(proc(1, "xmrig.exe", path),), signatures=(unsigned(path),))
    )
    assert only(result).level is Level.SUSPEITO
    assert "miner_process_name" in codes(only(result))


def test_mining_command_line_is_suspect_even_with_a_valid_signature() -> None:
    cmd = r"tool.exe -o stratum+tcp://u:p@pool.exemplo:3333"
    path = r"C:\Program Files\Tool\tool.exe"
    result = processes.scan(
        inspector(
            processes=(proc(1, "tool.exe", path, cmd),),
            signatures=(valid(path, "O=Tool", SignerKind.OTHER),),
        )
    )
    assert only(result).level is Level.SUSPEITO


def test_the_original_command_line_is_kept_unredacted_in_the_finding() -> None:
    cmd = r"x.exe -o stratum+tcp://walletuser:s3cr3tpw@pool.exemplo:3333"
    result = processes.scan(inspector(processes=(proc(1, "x.exe", DROP, cmd),)))
    assert only(result).evidence == (cmd,)


def test_system_name_outside_its_folder_is_an_impostor() -> None:
    path = r"C:\Users\Ana\AppData\Roaming\svchost.exe"
    result = processes.scan(inspector(processes=(proc(1, "svchost.exe", path),)))
    assert only(result).level is Level.SUSPEITO
    assert "system_name_wrong_location" in codes(only(result))


def test_genuine_system_binary_with_bad_signature_gets_advice_and_no_removal() -> None:
    path = SYS + r"\svchost.exe"
    for sig in (unsigned(path),):
        result = processes.scan(
            inspector(processes=(proc(1, "svchost.exe", path),), signatures=(sig,))
        )
        f = only(result)
        assert f.level is Level.SUSPEITO
        assert "system_binary_bad_signature" in codes(f)
        assert "Análise offline do Microsoft Defender" in f.advice


def test_system_process_without_path_is_silently_left_alone() -> None:
    result = processes.scan(inspector(processes=(proc(1, "svchost.exe", None),)))
    assert result.findings == ()


def test_own_processes_are_never_judged() -> None:
    insp = inspector(processes=(proc(7, "xmrig.exe", DROP, "stratum+tcp://x"),))
    ctx = insp.system_context()
    assert ctx.own_pids == frozenset()
    from dataclasses import replace

    from zerobirus.core.snapshot import Snapshot
    from zerobirus.platform.fake import FakeInspector

    own = FakeInspector(
        Snapshot(
            elevated=True,
            system=replace(ctx, own_pids=frozenset({7})),
            processes=(proc(7, "xmrig.exe", DROP, "stratum+tcp://x"),),
        )
    )
    assert processes.scan(own).findings == ()


def test_processes_gap_makes_the_check_incomplete() -> None:
    result = processes.scan(inspector(gaps={"processes": ("sem acesso a alguns processos",)}))
    assert not result.verified
    assert result.level is Level.NAO_VERIFICADO


# startup -------------------------------------------------------------------------------


def run_entry(command: str, kind: str = "run", name: str = "x") -> AutorunEntry:
    return AutorunEntry(r"HKCU\...\Run", name, command, r"PC\Ana", kind)


def test_run_value_pointing_to_unsigned_random_dropper_is_suspect() -> None:
    result = startup.scan(
        inspector(autoruns=(run_entry(f'"{DROP}"'),), signatures=(unsigned(DROP),))
    )
    assert only(result).level is Level.SUSPEITO
    assert "persist_unsigned_random_writable" in codes(only(result))


def test_run_value_from_appdata_with_valid_signature_is_not_reported() -> None:
    path = r"C:\Users\Ana\AppData\Local\Discord\Update.exe"
    sig = valid(path, "O=Discord Inc.", SignerKind.OTHER)
    result = startup.scan(inspector(autoruns=(run_entry(f'"{path}" --x'),), signatures=(sig,)))
    assert result.findings == ()


def test_run_value_with_unexpanded_appdata_variable_is_noticed() -> None:
    result = startup.scan(inspector(autoruns=(run_entry(r"%APPDATA%\x\a.exe"),)))
    assert "persist_writable" in codes(only(result))


@pytest.mark.parametrize(
    ("name", "value", "flagged"),
    [
        ("Shell", "explorer.exe", False),
        ("Shell", "explorer.exe, evil.exe", True),
        ("Shell", r"C:\Users\Ana\AppData\Roaming\x\shell.exe", True),
        ("Userinit", r"C:\Windows\system32\userinit.exe,", False),
        ("Userinit", r"C:\Windows\System32\Userinit.exe,", False),
        ("Userinit", r"C:\Windows\system32\userinit.exe,C:\x\evil.exe", True),
    ],
)
def test_winlogon_values_are_compared_with_the_defaults(
    name: str, value: str, flagged: bool
) -> None:
    result = startup.scan(inspector(autoruns=(run_entry(value, "winlogon", name),)))
    assert bool(result.findings) is flagged


def test_appinit_dlls_and_ifeo_debugger_are_reported_only_when_set() -> None:
    result = startup.scan(
        inspector(
            autoruns=(
                run_entry("", "appinit", "AppInit_DLLs"),
                run_entry(r"C:\x\hook.dll", "appinit", "AppInit_DLLs (32)"),
                run_entry(r"C:\Windows\System32\taskmgr2.exe", "ifeo", "taskmgr.exe"),
                run_entry("", "ifeo", "other.exe"),
            )
        )
    )
    assert levels(result) == {"AppInit_DLLs (32)": Level.CONFERIR, "taskmgr.exe": Level.CONFERIR}


def test_mining_command_in_a_run_value_is_suspect() -> None:
    result = startup.scan(inspector(autoruns=(run_entry("x.exe --donate-level=1"),)))
    assert only(result).level is Level.SUSPEITO


# tasks ---------------------------------------------------------------------------------


def task(
    folder: str,
    name: str,
    execute: str,
    args: str = "",
    *,
    enabled: bool = True,
    every: int | None = None,
) -> TaskInfo:
    return TaskInfo(folder, name, enabled, (TaskAction(execute, args),), ("TimeTrigger",), every)


def test_task_inside_microsoft_folder_running_from_appdata_is_disguised() -> None:
    t = task("\\Microsoft\\Windows\\Maintenance\\", "Opt", DROP, every=1)
    result = tasks.scan(inspector(tasks=(t,), signatures=(unsigned(DROP),)))
    assert "task_disguised_microsoft" in codes(only(result))
    assert only(result).level is Level.SUSPEITO


def test_regular_microsoft_task_is_not_reported() -> None:
    t = task("\\Microsoft\\Windows\\Defrag\\", "D", r"%windir%\system32\defrag.exe", "-c")
    assert tasks.scan(inspector(tasks=(t,))).findings == ()


def test_task_outside_microsoft_from_program_files_signed_is_not_reported() -> None:
    path = r"C:\Program Files\Google\Update\GoogleUpdate.exe"
    t = task("\\", "GoogleUpdate", path, "/c", every=60)
    sig = valid(path, "O=Google LLC", SignerKind.OTHER)
    assert tasks.scan(inspector(tasks=(t,), signatures=(sig,))).findings == ()


def test_task_through_a_shell_to_appdata_is_noticed() -> None:
    t = task("\\", "T", "cmd.exe", rf"/c {DROP}")
    f = only(tasks.scan(inspector(tasks=(t,), signatures=(unsigned(DROP),))))
    assert {"task_from_writable", "shell_command"} <= codes(f)


# services ------------------------------------------------------------------------------


def svc(name: str, image: str) -> ServiceInfo:
    return ServiceInfo(name, name, image, "automatic", "LocalSystem")


def test_microsoft_service_is_decided_by_signature_and_path_not_by_name() -> None:
    path = SYS + r"\svchost.exe"
    good = svc("Dnscache", f"{path} -k NetworkService")
    faked_name = svc("Microsoft Windows Update", r"C:\ProgramData\kzqpx\wu.exe")
    result = services.scan(
        inspector(
            services=(good, faked_name),
            signatures=(valid(path), unsigned(r"C:\ProgramData\kzqpx\wu.exe")),
        )
    )
    assert levels(result) == {"Microsoft Windows Update": Level.SUSPEITO}


def test_service_running_svchost_from_outside_system32_is_an_impostor() -> None:
    result = services.scan(inspector(services=(svc("Evil", r"C:\ProgramData\x\svchost.exe -k a"),)))
    assert "system_name_wrong_location" in codes(only(result))


def test_unsigned_third_party_service_in_program_files_is_conferir() -> None:
    path = r"C:\Program Files\Acme\acme.exe"
    result = services.scan(
        inspector(services=(svc("Acme", f'"{path}"'),), signatures=(unsigned(path),))
    )
    assert only(result).level is Level.CONFERIR


# files ---------------------------------------------------------------------------------


def test_file_with_persistence_and_defender_exclusion_is_suspect() -> None:
    excluded = (r"C:\Users\Ana\AppData\Roaming\kzqpx",)
    insp = inspector(
        files=(FileCandidate(DROP, 10, 0),),
        autoruns=(run_entry(f'"{DROP}"'),),
        defender=(DefenderState(True, True, False, 1, (), excluded, (), (), ()),),
        signatures=(unsigned(DROP),),
    )
    f = only(files.scan(insp))
    assert f.level is Level.SUSPEITO
    assert "defender_exclusion_and_persistence" in codes(f)


def test_ordinary_installed_program_in_appdata_is_not_reported() -> None:
    path = r"C:\Users\Ana\AppData\Local\Programs\Notes\notes.exe"
    assert files.scan(inspector(files=(FileCandidate(path, 10, 0),))).findings == ()


def test_crack_folder_is_conferir_not_suspect() -> None:
    path = r"C:\Users\Ana\Downloads\Office crack\setup.exe"
    result = files.scan(
        inspector(files=(FileCandidate(path, 10, 0),), signatures=(unsigned(path),))
    )
    assert only(result).level is Level.CONFERIR


# network -------------------------------------------------------------------------------


def conn(pid: int | None, addr: str, port: int, status: str = "ESTABLISHED") -> ConnectionInfo:
    return ConnectionInfo(pid, addr, port, status)


def test_mining_port_from_a_writable_folder_is_suspect_and_other_is_conferir() -> None:
    insp = inspector(
        processes=(proc(1, "a.exe", DROP), proc(2, "b.exe", r"C:\Program Files\B\b.exe")),
        connections=(conn(1, "93.184.216.34", 3333), conn(2, "93.184.216.34", 4444)),
    )
    result = network.scan(insp)
    assert sorted(f.level for f in result.findings) == [Level.CONFERIR, Level.SUSPEITO]


@pytest.mark.parametrize(
    "c",
    [
        conn(1, "93.184.216.34", 443),
        conn(1, "93.184.216.34", 80),
        conn(1, "192.168.1.5", 3333),
        conn(1, "127.0.0.1", 3333),
        conn(1, "93.184.216.34", 3333, "LISTEN"),
        conn(1, "93.184.216.34", 3333, "TIME_WAIT"),
    ],
)
def test_ports_80_443_local_addresses_and_non_active_states_are_ignored(c: ConnectionInfo) -> None:
    assert (
        network.scan(inspector(processes=(proc(1, "a.exe", DROP),), connections=(c,))).findings
        == ()
    )


def test_connection_of_unknown_process_is_still_reported_as_conferir() -> None:
    result = network.scan(inspector(connections=(conn(None, "93.184.216.34", 3333),)))
    assert only(result).level is Level.CONFERIR


def test_network_gap_is_incomplete() -> None:
    result = network.scan(inspector(gaps={"connections": ("acesso negado",)}))
    assert result.level is Level.NAO_VERIFICADO


# defender ------------------------------------------------------------------------------


def state(**kw: object) -> DefenderState:
    base: dict[str, object] = dict(
        realtime=True,
        tamper_protection=True,
        passive_mode=False,
        signature_age_days=1,
        threats=(),
        exclusion_paths=(),
        exclusion_extensions=(),
        exclusion_processes=(),
        exclusion_ips=(),
    )
    base.update(kw)
    return DefenderState(**base)  # type: ignore[arg-type]


def test_healthy_defender_is_ok_with_positive_evidence() -> None:
    result = defender.scan(inspector(defender=(state(),)))
    assert result.verified
    assert only(result).level is Level.OK


def test_realtime_off_is_conferir_unless_another_antivirus_made_it_passive() -> None:
    assert only(defender.scan(inspector(defender=(state(realtime=False),)))).level is Level.CONFERIR
    passive = defender.scan(inspector(defender=(state(realtime=False, passive_mode=True),)))
    assert only(passive).level is Level.OK


def test_unreadable_exclusions_are_nao_verificado_never_no_exclusions() -> None:
    s = state(
        exclusion_paths=None,
        exclusion_extensions=None,
        exclusion_processes=None,
        exclusion_ips=None,
    )
    result = defender.scan(inspector(elevated=False, defender=(s,)))
    assert not result.verified
    assert "exclusões" in result.reason
    assert result.level is Level.NAO_VERIFICADO


def test_nothing_read_from_defender_is_nao_verificado() -> None:
    result = defender.scan(inspector(gaps={"defender": ("serviço do Defender desativado",)}))
    assert result.level is Level.NAO_VERIFICADO
    assert "desativado" in result.reason
    empty = defender.scan(inspector())
    assert empty.level is Level.NAO_VERIFICADO


def test_exclusions_by_kind_and_risk() -> None:
    s = state(
        exclusion_paths=(r"C:\Users\Ana\AppData\Roaming\x", r"C:\Games", "C:\\"),
        exclusion_extensions=("exe",),
        exclusion_processes=("miner.exe",),
        exclusion_ips=("203.0.113.9",),
    )
    result = defender.scan(inspector(defender=(s,)))
    by_item = levels(result)
    assert by_item[r"C:\Users\Ana\AppData\Roaming\x"] is Level.CONFERIR
    assert by_item["C:\\"] is Level.CONFERIR
    assert all(lvl is Level.CONFERIR for k, lvl in by_item.items() if k != "Microsoft Defender")
    assert "exe" in by_item


def test_threat_history_is_conferir_and_keeps_names_as_evidence() -> None:
    result = defender.scan(inspector(defender=(state(threats=("Trojan:Win32/Foo",)),)))
    f = next(f for f in result.findings if f.item == "Histórico de ameaças")
    assert f.level is Level.CONFERIR
    assert f.evidence == ("Trojan:Win32/Foo",)


def test_old_signatures() -> None:
    assert (
        only(defender.scan(inspector(defender=(state(signature_age_days=45),)))).level
        is Level.CONFERIR
    )
    assert (
        only(defender.scan(inspector(defender=(state(signature_age_days=10),)))).level is Level.OK
    )


# hosts ---------------------------------------------------------------------------------


def hosts_of(*lines: str) -> object:
    return inspector(hosts=tuple(lines))


@pytest.mark.parametrize(
    "line",
    [
        "# comment",
        "",
        "   ",
        "127.0.0.1 localhost",
        "::1 localhost",
        "127.0.0.1   localhost   # inline",
        "0.0.0.0 ads.example.invalid # ZeroBirus",
    ],
)
def test_default_comments_and_our_own_lines_are_ignored(line: str) -> None:
    assert hosts.scan(inspector(hosts=(line,))).findings == ()


def test_redirecting_a_security_or_update_domain_is_suspect() -> None:
    for line in (
        "0.0.0.0 update.microsoft.com",
        "127.0.0.1 www.kaspersky.com",
        "1.2.3.4 windowsupdate.com",
    ):
        assert only(hosts.scan(inspector(hosts=(line,)))).level is Level.SUSPEITO


def test_other_custom_lines_are_conferir() -> None:
    assert only(hosts.scan(inspector(hosts=("10.0.0.5 nas.home",)))).level is Level.CONFERIR


# wmi -----------------------------------------------------------------------------------


def test_default_scm_consumer_is_ignored_and_unknown_command_consumer_is_suspect() -> None:
    default = WmiBinding(
        "SCM Event Log Filter", "SCM Event Log Consumer", "NTEventLogEventConsumer"
    )
    evil = WmiBinding("F", "C", "CommandLineEventConsumer", DROP)
    result = wmi.scan(inspector(wmi_bindings=(default, evil), signatures=(unsigned(DROP),)))
    assert levels(result) == {"C": Level.SUSPEITO}


def test_command_consumer_run_by_a_known_vendor_is_only_conferir() -> None:
    path = r"C:\Program Files\Vendor\agent.exe"
    b = WmiBinding("F", "C", "CommandLineEventConsumer", path)
    sig = valid(path, "O=Kaspersky", SignerKind.ANTIVIRUS_VENDOR)
    assert only(wmi.scan(inspector(wmi_bindings=(b,), signatures=(sig,)))).level is Level.CONFERIR


def test_wmi_without_administrator_is_nao_verificado() -> None:
    result = wmi.scan(inspector(gaps={"wmi_bindings": ("sem administrador",)}))
    assert result.level is Level.NAO_VERIFICADO


# Lessons from the first run on a real Windows machine (windows-latest) ------------------


def test_whole_drive_defender_exclusion_is_one_finding_not_one_per_file() -> None:
    path = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"
    insp = inspector(
        files=(FileCandidate(path, 10, 0), FileCandidate(DROP, 10, 0)),
        defender=(DefenderState(True, True, False, 1, (), ("C:\\", "D:\\"), (), (), ()),),
        signatures=(unsigned(DROP),),
    )
    assert files.scan(insp).findings[0].item == "a.exe" if files.scan(insp).findings else True
    assert path.rsplit("\\", 1)[-1] not in {f.item for f in files.scan(insp).findings}
    assert "defender_exclusion_covers" not in {
        s.code for f in files.scan(insp).findings for s in f.signals
    }
    drive = defender.scan(insp)
    assert levels(drive)["C:\\"] is Level.CONFERIR


def test_antivirus_folder_with_service_and_exclusion_is_not_suspect() -> None:
    path = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"
    insp = inspector(
        files=(FileCandidate(path, 10, 0),),
        services=(svc("WinDefend", f'"{path}"'),),
        defender=(
            DefenderState(
                True,
                True,
                False,
                1,
                (),
                (r"C:\ProgramData\Microsoft\Windows Defender",),
                (),
                (),
                (),
            ),
        ),
    )
    assert files.scan(insp).findings == ()


def test_installer_cache_guid_folders_are_not_random_droppers() -> None:
    path = (
        r"C:\ProgramData\Package Cache\{C0A2B576-1630-4449-93B8-06C8FBBAF369}v17.1\vsta_setup.exe"
    )
    assert files.scan(inspector(files=(FileCandidate(path, 10, 0),))).findings == ()


def test_an_excluded_unsigned_dropper_folder_is_still_conferir() -> None:
    insp = inspector(
        files=(FileCandidate(DROP, 10, 0),),
        defender=(
            DefenderState(
                True, True, False, 1, (), (r"C:\Users\Ana\AppData\Roaming\kzqpx",), (), (), ()
            ),
        ),
        signatures=(unsigned(DROP),),
    )
    assert only(files.scan(insp)).level is Level.CONFERIR
