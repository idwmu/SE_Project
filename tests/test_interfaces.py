import subprocess
import sys

import pytest

from pps import interfaces
from pps.interfaces import (
    CaptureMode,
    CapturePermissionError,
    InterfaceError,
    InterfaceInfo,
    InterfaceNotFoundError,
    MonitorModeError,
)

IW_WITH_MONITOR = """\
Wiphy phy0
\tSupported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * AP
\t\t * monitor
\tBand 1:
"""
IW_WITHOUT_MONITOR = IW_WITH_MONITOR.replace("\t\t * monitor\n", "")


def ok(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class FakeRunner:
    """Records argv lists; `responses` maps a command prefix to a result or exception."""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    def __call__(self, cmd):
        cmd = list(cmd)
        self.calls.append(cmd)
        for prefix, result in self.responses.items():
            if cmd[: len(prefix)] == list(prefix):
                if isinstance(result, Exception):
                    raise result
                return result
        return ok()


def raw(name, *, up=True, loopback=False, mac="aa:bb:cc:dd:ee:ff", ips=()):
    return {
        "name": name,
        "description": name,
        "mac": mac,
        "ips": tuple(ips),
        "is_up": up,
        "is_loopback": loopback,
    }


@pytest.fixture
def sysfs(tmp_path):
    """Fake /sys/class/net with a wired NIC, a Wi-Fi NIC and a monitor-mode device."""
    root = tmp_path / "net"
    (root / "eth0").mkdir(parents=True)
    (root / "eth0" / "type").write_text("1\n")
    (root / "wlan0" / "wireless").mkdir(parents=True)
    (root / "wlan0" / "type").write_text("1\n")
    (root / "wlan0" / "phy80211").symlink_to("../../ieee80211/phy0")
    (root / "mon0" / "wireless").mkdir(parents=True)
    (root / "mon0" / "type").write_text("803\n")
    (root / "mon0" / "phy80211").symlink_to("../../ieee80211/phy1")
    return root


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(interfaces, "_platform", lambda: "linux")


@pytest.fixture
def scapy_ifaces(monkeypatch, linux):
    records = [raw("lo", loopback=True), raw("eth0"), raw("wlan0"), raw("mon0")]
    monkeypatch.setattr(interfaces, "_scapy_records", lambda: records)
    return records


def info(name="wlan0", **kw):
    base = dict(
        name=name,
        description=name,
        mac=None,
        ips=(),
        is_up=True,
        is_loopback=False,
        is_wireless=False,
        monitor_capable=False,
        in_monitor_mode=False,
    )
    base.update(kw)
    return InterfaceInfo(**base)


# --- listing -----------------------------------------------------------------


def test_list_classifies_wired_wireless_and_monitor(scapy_ifaces, sysfs):
    runner = FakeRunner({("iw", "phy"): ok(IW_WITH_MONITOR)})
    by_name = {i.name: i for i in interfaces.list_interfaces(sysfs_root=sysfs, runner=runner)}

    assert not by_name["eth0"].is_wireless
    assert by_name["eth0"].modes == (CaptureMode.PROMISCUOUS,)

    wlan = by_name["wlan0"]
    assert wlan.is_wireless and wlan.monitor_capable is True and not wlan.in_monitor_mode
    assert wlan.modes == (CaptureMode.PROMISCUOUS, CaptureMode.MONITOR)

    assert by_name["mon0"].in_monitor_mode
    assert CaptureMode.MONITOR in by_name["mon0"].modes
    assert by_name["lo"].is_loopback


def test_driver_without_monitor_support(scapy_ifaces, sysfs):
    runner = FakeRunner({("iw", "phy"): ok(IW_WITHOUT_MONITOR)})
    wlan = {i.name: i for i in interfaces.list_interfaces(sysfs_root=sysfs, runner=runner)}[
        "wlan0"
    ]
    assert wlan.is_wireless and wlan.monitor_capable is False
    assert wlan.modes == (CaptureMode.PROMISCUOUS,)


@pytest.mark.parametrize(
    "response",
    [FileNotFoundError("iw"), subprocess.TimeoutExpired("iw", 10), ok(returncode=1)],
    ids=["iw-missing", "iw-hangs", "iw-fails"],
)
def test_unknown_monitor_support_is_none_not_a_crash(scapy_ifaces, sysfs, response):
    runner = FakeRunner({("iw", "phy"): response})
    wlan = {i.name: i for i in interfaces.list_interfaces(sysfs_root=sysfs, runner=runner)}[
        "wlan0"
    ]
    assert wlan.is_wireless and wlan.monitor_capable is None
    assert CaptureMode.MONITOR not in wlan.modes


def test_phy_name_from_sysfs_is_validated_before_calling_iw(scapy_ifaces, sysfs):
    (sysfs / "wlan0" / "phy80211").unlink()
    (sysfs / "wlan0" / "phy80211").symlink_to("../../ieee80211/--evil")
    runner = FakeRunner()
    interfaces.list_interfaces(sysfs_root=sysfs, runner=runner)
    assert not any("--evil" in c for call in runner.calls for c in call)


def test_non_linux_reports_unknown_wireless_details(monkeypatch, sysfs):
    monkeypatch.setattr(interfaces, "_platform", lambda: "darwin")
    monkeypatch.setattr(interfaces, "_scapy_records", lambda: [raw("en0")])
    [en0] = interfaces.list_interfaces(sysfs_root=sysfs)
    assert not en0.is_wireless and en0.monitor_capable is None
    assert en0.modes == (CaptureMode.PROMISCUOUS,)


def test_backend_failure_becomes_interface_error(monkeypatch):
    import scapy.interfaces

    def boom():
        raise OSError("no libpcap")

    monkeypatch.setattr(scapy.interfaces, "get_if_list", boom)
    with pytest.raises(InterfaceError, match="libpcap.*Npcap"):
        interfaces.list_interfaces()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux loopback expected")
def test_real_scapy_enumeration_smoke():
    found = interfaces.list_interfaces()
    assert any(i.is_loopback for i in found)
    assert all(isinstance(i, InterfaceInfo) for i in found)


def test_parse_iw_output():
    assert interfaces._parse_iw_monitor_support(IW_WITH_MONITOR) is True
    assert interfaces._parse_iw_monitor_support(IW_WITHOUT_MONITOR) is False
    assert interfaces._parse_iw_monitor_support("") is False
    # 'monitor' appearing outside the supported-modes block must not count
    assert interfaces._parse_iw_monitor_support("Foo:\n\t * monitor\n") is False


# --- selection ---------------------------------------------------------------


def test_default_prefers_up_wireless_then_up_non_loopback():
    lo = info("lo", is_loopback=True)
    eth = info("eth0")
    wlan = info("wlan0", is_wireless=True)
    assert interfaces.select_interface(interfaces=[lo, eth, wlan]).name == "wlan0"
    assert interfaces.select_interface(interfaces=[lo, eth]).name == "eth0"
    down_wlan = info("wlan0", is_wireless=True, is_up=False)
    assert interfaces.select_interface(interfaces=[lo, down_wlan, eth]).name == "eth0"


def test_default_fails_clearly_when_nothing_is_up():
    only_down = [info("eth0", is_up=False), info("lo", is_loopback=True)]
    with pytest.raises(InterfaceNotFoundError, match="No interface is up.*eth0"):
        interfaces.select_interface(interfaces=only_down)


def test_unknown_name_lists_available_interfaces():
    with pytest.raises(InterfaceNotFoundError, match=r"'nope' not found.*eth0, wlan0"):
        interfaces.select_interface("nope", interfaces=[info("eth0"), info("wlan0")])


def test_long_interface_lists_are_truncated_in_messages():
    many = [info(f"veth{i}") for i in range(20)]
    with pytest.raises(InterfaceNotFoundError, match=r"veth7 \(\+12 more\)") as exc:
        interfaces.select_interface("nope", interfaces=many)
    assert "veth8" not in str(exc.value)


def test_no_interfaces_at_all():
    with pytest.raises(InterfaceNotFoundError, match="No network interfaces"):
        interfaces.select_interface(interfaces=[])


def test_select_by_name_and_mode():
    wlan = info("wlan0", is_wireless=True, monitor_capable=True)
    chosen = interfaces.select_interface("wlan0", CaptureMode.MONITOR, interfaces=[wlan])
    assert chosen is wlan
    assert interfaces.select_interface("wlan0", CaptureMode.PROMISCUOUS, interfaces=[wlan])


@pytest.mark.parametrize(
    ("iface", "reason"),
    [
        (info("eth0"), "not a wireless interface"),
        (info("wlan0", is_wireless=True, monitor_capable=None), "is 'iw' installed"),
        (info("wlan0", is_wireless=True, monitor_capable=False), "driver does not report"),
    ],
)
def test_monitor_request_explains_why_unavailable_and_mentions_promiscuous(iface, reason):
    with pytest.raises(MonitorModeError, match=reason) as exc:
        interfaces.select_interface(iface.name, CaptureMode.MONITOR, interfaces=[iface])
    assert "Promiscuous mode works on any interface" in str(exc.value)


def test_info_to_dict_is_json_friendly():
    d = info("wlan0", ips=("10.0.0.2",), is_wireless=True, monitor_capable=True).to_dict()
    assert d["ips"] == ["10.0.0.2"]
    assert d["modes"] == ["promiscuous", "monitor"]


# --- permissions ---------------------------------------------------------------

RAW = 1 << interfaces.CAP_NET_RAW
ADMIN = 1 << interfaces.CAP_NET_ADMIN


def perms(monkeypatch, *, platform="linux", root=False, caps=0, bpf=False):
    monkeypatch.setattr(interfaces, "_platform", lambda: platform)
    monkeypatch.setattr(interfaces, "_is_root", lambda: root)
    monkeypatch.setattr(interfaces, "_linux_capabilities", lambda: caps)
    monkeypatch.setattr(interfaces, "_bpf_devices_accessible", lambda: bpf)


def test_unprivileged_linux_gets_actionable_message(monkeypatch):
    perms(monkeypatch, caps=0)
    problem = interfaces.capture_permission_problem()
    assert "CAP_NET_RAW" in problem and "setcap cap_net_raw=eip" in problem
    with pytest.raises(CapturePermissionError, match="CAP_NET_RAW"):
        interfaces.require_capture_permission()


def test_linux_permission_cases(monkeypatch):
    perms(monkeypatch, root=True)
    assert interfaces.capture_permission_problem(need_admin=True) is None
    perms(monkeypatch, caps=RAW)
    assert interfaces.capture_permission_problem() is None
    problem = interfaces.capture_permission_problem(need_admin=True)
    assert "CAP_NET_ADMIN" in problem and "CAP_NET_RAW" not in problem.split("grant")[0]
    perms(monkeypatch, caps=RAW | ADMIN)
    assert interfaces.capture_permission_problem(need_admin=True) is None
    perms(monkeypatch, caps=None)  # /proc unreadable: assume missing rather than guess
    assert interfaces.capture_permission_problem() is not None


def test_macos_needs_bpf_access(monkeypatch):
    perms(monkeypatch, platform="darwin", bpf=False)
    assert "/dev/bpf" in interfaces.capture_permission_problem()
    perms(monkeypatch, platform="darwin", bpf=True)
    assert interfaces.capture_permission_problem() is None


def test_windows_is_not_pre_checked(monkeypatch):
    perms(monkeypatch, platform="win32")
    assert interfaces.capture_permission_problem() is None


def test_capability_mask_is_parsed_from_proc_status(monkeypatch):
    monkeypatch.setattr(
        interfaces, "_read_lines", lambda p: ["Name:\tpython", "CapEff:\t0000000000003000"]
    )
    assert interfaces._linux_capabilities() == RAW | ADMIN
    monkeypatch.setattr(interfaces, "_read_lines", lambda p: [])
    assert interfaces._linux_capabilities() is None


# --- switching monitor mode ------------------------------------------------------


def _states(before, after):
    seq = iter([before, after])
    return lambda: next(seq)


def wifi(**kw):
    return info("wlan0", is_wireless=True, monitor_capable=True, **kw)


def test_enable_monitor_runs_down_retype_up_without_a_shell(monkeypatch):
    perms(monkeypatch, root=True)
    runner = FakeRunner()
    after = wifi(in_monitor_mode=True)
    result = interfaces.set_monitor_mode(
        "wlan0", runner=runner, interfaces=_states([wifi()], [after])
    )
    assert runner.calls == [
        ["ip", "link", "set", "wlan0", "down"],
        ["iw", "dev", "wlan0", "set", "type", "monitor"],
        ["ip", "link", "set", "wlan0", "up"],
    ]
    assert result.in_monitor_mode


def test_disable_monitor_returns_to_managed(monkeypatch):
    perms(monkeypatch, root=True)
    runner = FakeRunner()
    interfaces.set_monitor_mode(
        "wlan0",
        False,
        runner=runner,
        interfaces=_states([wifi(in_monitor_mode=True)], [wifi()]),
    )
    assert ["iw", "dev", "wlan0", "set", "type", "managed"] in runner.calls


def test_already_in_requested_mode_changes_nothing(monkeypatch):
    perms(monkeypatch, root=True)
    runner = FakeRunner()
    current = wifi(in_monitor_mode=True)
    result = interfaces.set_monitor_mode("wlan0", runner=runner, interfaces=lambda: [current])
    assert result is current
    assert runner.calls == []


def test_failure_restores_interface_and_reports_driver_error(monkeypatch):
    perms(monkeypatch, root=True)
    failed = ok(stderr="command failed: Operation not supported", returncode=95)
    runner = FakeRunner({("iw", "dev"): failed})
    with pytest.raises(MonitorModeError, match="Operation not supported"):
        interfaces.set_monitor_mode("wlan0", runner=runner, interfaces=lambda: [wifi()])
    assert runner.calls[-1] == ["ip", "link", "set", "wlan0", "up"]


def test_failure_bringing_interface_up_is_reported(monkeypatch):
    perms(monkeypatch, root=True)
    runner = FakeRunner({("ip", "link", "set", "wlan0", "up"): ok(stderr="busy", returncode=2)})
    with pytest.raises(MonitorModeError, match="could not be brought up: busy"):
        interfaces.set_monitor_mode("wlan0", runner=runner, interfaces=lambda: [wifi()])


def test_missing_tool_is_a_clear_error(monkeypatch):
    perms(monkeypatch, root=True)
    runner = FakeRunner({("ip",): FileNotFoundError("ip")})
    with pytest.raises(MonitorModeError, match="'ip' is not installed"):
        interfaces.set_monitor_mode("wlan0", runner=runner, interfaces=lambda: [wifi()])


def test_no_privileges_means_no_commands_run(monkeypatch):
    perms(monkeypatch, caps=RAW)  # has NET_RAW but not NET_ADMIN
    runner = FakeRunner()
    with pytest.raises(CapturePermissionError, match="CAP_NET_ADMIN"):
        interfaces.set_monitor_mode("wlan0", runner=runner, interfaces=lambda: [wifi()])
    assert runner.calls == []


def test_unsupported_os_and_wired_and_unknown_interfaces(monkeypatch):
    perms(monkeypatch, platform="darwin", root=True)
    with pytest.raises(MonitorModeError, match="only supported on Linux"):
        interfaces.set_monitor_mode("en0", interfaces=lambda: [])

    perms(monkeypatch, root=True)
    runner = FakeRunner()
    with pytest.raises(MonitorModeError, match="not a wireless interface"):
        interfaces.set_monitor_mode("eth0", runner=runner, interfaces=lambda: [info("eth0")])
    with pytest.raises(InterfaceNotFoundError):
        interfaces.set_monitor_mode("wlan9", runner=runner, interfaces=lambda: [wifi()])
    assert runner.calls == []


@pytest.mark.parametrize("bad", ["-h", "wlan0; reboot", "", "a" * 16, "--version", "$(id)"])
def test_interface_names_are_validated_before_use(monkeypatch, bad):
    perms(monkeypatch, root=True)
    runner = FakeRunner()
    with pytest.raises(InterfaceError, match="Invalid interface name"):
        interfaces.set_monitor_mode(bad, runner=runner, interfaces=lambda: [wifi()])
    assert runner.calls == []


def test_info_is_immutable():
    with pytest.raises(AttributeError):
        info().name = "x"  # type: ignore[misc]

