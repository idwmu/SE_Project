"""Capture interfaces: listing, selection and monitor mode (PPS-F-001).

Two capture modes are kept deliberately distinct:

* **Promiscuous** mode makes any NIC (wired or wireless) hand up frames not
  addressed to it. On Wi-Fi this only shows traffic of the network the
  adapter is associated with, as ordinary Ethernet frames.
* **Monitor** mode is wireless-only. The adapter stops associating and
  delivers raw 802.11 frames (RadioTap) from the air, which needs a driver
  that supports it.

Scapy enumerates interfaces on every platform. Everything wireless-specific
(is it Wi-Fi, can it monitor, is it monitoring now) is read from Linux sysfs
and ``iw``; elsewhere those fields are reported as unknown rather than
guessed. Failures (no backend, no permission, no ``iw``, no driver support)
raise :class:`InterfaceError` subclasses with an actionable message.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any

SYSFS_NET = Path("/sys/class/net")

# Linux ARPHRD_* link types that mean "this device delivers raw 802.11 frames".
_ARPHRD_IEEE80211_PRISM = 802
_ARPHRD_IEEE80211_RADIOTAP = 803
_MONITOR_LINK_TYPES = frozenset({_ARPHRD_IEEE80211_PRISM, _ARPHRD_IEEE80211_RADIOTAP})

CAP_NET_ADMIN = 12
CAP_NET_RAW = 13

IFF_UP = 0x1

# Linux IFNAMSIZ is 16 including the NUL. Names go to ip/iw as argv (never a
# shell), but are still validated so an odd name cannot become an option.
_IFNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,14}$")
_PHY = re.compile(r"^phy\d+$")

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


class InterfaceError(RuntimeError):
    """Base class for interface listing, selection and mode errors."""


class InterfaceNotFoundError(InterfaceError):
    """The requested interface does not exist (or none exist at all)."""


class CapturePermissionError(InterfaceError):
    """The process lacks the privileges needed to capture or change modes."""


class MonitorModeError(InterfaceError):
    """Monitor mode is unsupported or could not be switched."""


class CaptureMode(str, Enum):
    PROMISCUOUS = "promiscuous"
    MONITOR = "monitor"


@dataclass(frozen=True)
class InterfaceInfo:
    """One capture interface.

    ``is_up`` means administratively up (IFF_UP), not that a link exists.
    ``monitor_capable`` is ``None`` when it could not be determined (no
    ``iw``, non-Linux, ...); only ``True`` makes monitor mode available.
    """

    name: str
    description: str
    mac: str | None
    ips: tuple[str, ...]
    is_up: bool
    is_loopback: bool
    is_wireless: bool
    monitor_capable: bool | None
    in_monitor_mode: bool

    @property
    def modes(self) -> tuple[CaptureMode, ...]:
        """Capture modes this interface can be used in right now."""
        modes = [CaptureMode.PROMISCUOUS]
        if self.monitor_capable or self.in_monitor_mode:
            modes.append(CaptureMode.MONITOR)
        return tuple(modes)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ips"] = list(self.ips)
        d["modes"] = [m.value for m in self.modes]
        return d


def _run(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(cmd), capture_output=True, text=True, timeout=10, check=False)


def _platform() -> str:
    return sys.platform


def _flag_names(flags: Any) -> list[str]:
    """Scapy exposes flags as an int on some platforms, a '+'-joined FlagValue on Linux."""
    if isinstance(flags, int):
        return ["UP"] if flags & IFF_UP else []
    return str(flags).split("+") if flags else []


def _scapy_records() -> list[dict[str, Any]]:
    """Raw per-interface data from Scapy, one dict per interface."""
    try:
        import scapy.arch  # noqa: F401  (initialises conf.ifaces)
        from scapy.config import conf
        from scapy.interfaces import get_if_list

        # get_if_list() gives Npcap device paths on Windows but plain names elsewhere,
        # so match each entry against both the friendly and the network name.
        by_name: dict[str, Any] = {}
        for dev in conf.ifaces.values():
            for key in (getattr(dev, "name", None), getattr(dev, "network_name", None)):
                if key:
                    by_name[key] = dev
        records = []
        seen: set[int] = set()
        for listed in get_if_list():
            dev = by_name.get(listed)
            if dev is None or id(dev) in seen:  # adapter Scapy cannot resolve: skip, don't fail
                continue
            seen.add(id(dev))
            name = str(getattr(dev, "name", "") or listed)
            flags = _flag_names(getattr(dev, "flags", None))
            ips: list[str] = []
            for version in (4, 6):
                ips.extend(getattr(dev, "ips", {}).get(version, []))
            mac = getattr(dev, "mac", None)
            records.append(
                {
                    "name": name,
                    "description": str(getattr(dev, "description", "") or name),
                    "mac": mac or None,
                    "ips": tuple(ips),
                    "is_up": "UP" in flags,
                    "is_loopback": "LOOPBACK" in flags,
                }
            )
        return records
    except Exception as exc:
        raise InterfaceError(
            f"Could not enumerate network interfaces ({exc}). "
            "Check that a capture backend is installed (libpcap on Linux/macOS, Npcap on Windows)."
        ) from exc


def _read(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _parse_iw_monitor_support(output: str) -> bool:
    """Whether ``iw phy <phy> info`` lists 'monitor' under supported interface modes."""
    in_block = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Supported interface modes:"):
            in_block = True
        elif in_block and stripped.startswith("*"):
            if stripped.lstrip("* ").lower() == "monitor":
                return True
        elif in_block:
            break
    return False


def _monitor_capable(phy: str | None, runner: Runner) -> bool | None:
    if phy is None or not _PHY.match(phy):
        return None
    try:
        proc = runner(["iw", "phy", phy, "info"])
    except (OSError, subprocess.TimeoutExpired):  # iw missing or hung
        return None
    if proc.returncode != 0:
        return None
    return _parse_iw_monitor_support(proc.stdout)


def _wireless_details(name: str, sysfs: Path, runner: Runner) -> tuple[bool, bool | None, bool]:
    """(is_wireless, monitor_capable, in_monitor_mode) from Linux sysfs / iw."""
    base = sysfs / name
    phy_link = base / "phy80211"
    is_wireless = (base / "wireless").is_dir() or phy_link.exists()
    if not is_wireless:
        return False, False, False
    link_type = _read(base / "type")
    in_monitor = link_type is not None and link_type.isdigit() and (
        int(link_type) in _MONITOR_LINK_TYPES
    )
    phy = os.path.basename(os.readlink(phy_link)) if phy_link.is_symlink() else None
    return True, _monitor_capable(phy, runner), in_monitor


def list_interfaces(
    *, sysfs_root: Path = SYSFS_NET, runner: Runner = _run
) -> list[InterfaceInfo]:
    """All interfaces Scapy can see, enriched with wireless details on Linux."""
    linux = _platform().startswith("linux")
    result = []
    for rec in _scapy_records():
        if linux:
            wireless, capable, monitoring = _wireless_details(rec["name"], sysfs_root, runner)
        else:
            wireless, capable, monitoring = False, None, False
        result.append(
            InterfaceInfo(
                name=rec["name"],
                description=rec["description"],
                mac=rec["mac"],
                ips=rec["ips"],
                is_up=rec["is_up"],
                is_loopback=rec["is_loopback"],
                is_wireless=wireless,
                monitor_capable=capable,
                in_monitor_mode=monitoring,
            )
        )
    return result


def _default_interface(interfaces: Sequence[InterfaceInfo]) -> InterfaceInfo | None:
    """Prefer an up wireless NIC (the PPS target), then any up non-loopback NIC."""
    candidates = [i for i in interfaces if i.is_up and not i.is_loopback]
    for iface in candidates:
        if iface.is_wireless:
            return iface
    return candidates[0] if candidates else None


def _names(interfaces: Sequence[InterfaceInfo], limit: int = 8) -> str:
    """Comma-separated names; capped so a host with many virtual NICs stays readable."""
    names = [i.name for i in interfaces]
    shown = ", ".join(names[:limit])
    return shown + (f" (+{len(names) - limit} more)" if len(names) > limit else "")


def select_interface(
    name: str | None = None,
    mode: CaptureMode | None = None,
    *,
    interfaces: Sequence[InterfaceInfo] | None = None,
) -> InterfaceInfo:
    """Pick the capture interface, optionally checking it supports ``mode``.

    With ``name=None`` a sensible default is chosen (see ``_default_interface``).
    """
    available = list(list_interfaces() if interfaces is None else interfaces)
    if not available:
        raise InterfaceNotFoundError("No network interfaces were found on this device.")
    if name is None:
        chosen = _default_interface(available)
        if chosen is None:
            raise InterfaceNotFoundError(
                "No interface is up. Bring one up or choose one by name: " + _names(available)
            )
    else:
        chosen = next((i for i in available if i.name == name), None)
        if chosen is None:
            raise InterfaceNotFoundError(
                f"Interface {name!r} not found. Available: " + _names(available)
            )
    if mode is not None and mode not in chosen.modes:
        raise MonitorModeError(_mode_unavailable_message(chosen, mode))
    return chosen


def _mode_unavailable_message(iface: InterfaceInfo, mode: CaptureMode) -> str:
    if mode is not CaptureMode.MONITOR:
        return f"{iface.name} does not support {mode.value} mode."
    if not iface.is_wireless:
        reason = "it is not a wireless interface"
    elif iface.monitor_capable is None:
        reason = "support could not be determined (is 'iw' installed?)"
    else:
        reason = "its driver does not report monitor-mode support"
    return (
        f"Monitor mode is not available on {iface.name}: {reason}. "
        "Promiscuous mode works on any interface but only shows the network the adapter is on."
    )


def _linux_capabilities() -> int | None:
    """Effective capability bitmask of this process, or None if unreadable."""
    line = next(
        (ln for ln in (_read_lines(Path("/proc/self/status"))) if ln.startswith("CapEff:")),
        None,
    )
    try:
        return int(line.split()[1], 16) if line else None
    except (IndexError, ValueError):
        return None


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text().splitlines()
    except OSError:
        return []


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _bpf_devices_accessible() -> bool:
    devices = sorted(Path("/dev").glob("bpf*"))
    return bool(devices) and any(os.access(d, os.R_OK | os.W_OK) for d in devices)


def capture_permission_problem(*, need_admin: bool = False) -> str | None:
    """Why this process cannot capture (or reconfigure interfaces), or None if it can.

    ``need_admin`` additionally requires CAP_NET_ADMIN, needed to change
    interface modes. Windows is not checked: Scapy reports a missing Npcap or
    permission problem itself when capture starts.
    """
    platform = _platform()
    if platform.startswith("linux"):
        if _is_root():
            return None
        caps = _linux_capabilities()
        needed = [("CAP_NET_RAW", CAP_NET_RAW)] + (
            [("CAP_NET_ADMIN", CAP_NET_ADMIN)] if need_admin else []
        )
        missing = [n for n, bit in needed if caps is None or not (caps >> bit) & 1]
        if not missing:
            return None
        grant = ",".join(n.lower() for n, _ in needed)
        return (
            f"Missing {' and '.join(missing)}. Run as root, or grant the capability to the "
            f"Python interpreter: sudo setcap {grant}=eip \"$(readlink -f \"$(which python3)\")\""
        )
    if platform == "darwin":
        if _is_root() or _bpf_devices_accessible():
            return None
        return "No access to /dev/bpf*. Run as root or make the BPF devices readable by your user."
    return None


def require_capture_permission(*, need_admin: bool = False) -> None:
    problem = capture_permission_problem(need_admin=need_admin)
    if problem:
        raise CapturePermissionError(problem)


def _check_ifname(name: str) -> None:
    if not _IFNAME.match(name):
        raise InterfaceError(f"Invalid interface name: {name!r}")


def set_monitor_mode(
    name: str,
    enabled: bool = True,
    *,
    runner: Runner = _run,
    interfaces: Callable[[], Sequence[InterfaceInfo]] = list_interfaces,
) -> InterfaceInfo:
    """Switch a wireless interface to monitor (or back to managed) mode. Linux only.

    Needs root or CAP_NET_ADMIN. The interface is taken down, retyped with
    ``iw`` and brought back up; if retyping fails it is brought back up in
    its previous mode. A network manager may reclaim the interface afterwards.
    """
    _check_ifname(name)
    if not _platform().startswith("linux"):
        raise MonitorModeError(
            "Switching monitor mode is only supported on Linux; "
            "use promiscuous mode or put the adapter in monitor mode with the OS tools."
        )
    require_capture_permission(need_admin=True)
    iface = select_interface(
        name, CaptureMode.MONITOR if enabled else None, interfaces=list(interfaces())
    )
    if not iface.is_wireless:
        raise MonitorModeError(f"{name} is not a wireless interface.")
    if iface.in_monitor_mode == enabled:
        return iface

    target = "monitor" if enabled else "managed"

    def run(*cmd: str) -> subprocess.CompletedProcess[str]:
        try:
            return runner(cmd)
        except FileNotFoundError:
            raise MonitorModeError(f"'{cmd[0]}' is not installed; it is required.") from None
        except subprocess.TimeoutExpired:
            raise MonitorModeError(f"'{' '.join(cmd)}' timed out.") from None

    for cmd in (("ip", "link", "set", name, "down"), ("iw", "dev", name, "set", "type", target)):
        proc = run(*cmd)
        if proc.returncode != 0:
            run("ip", "link", "set", name, "up")  # best-effort restore of the old state
            detail = (proc.stderr or proc.stdout or "").strip()
            raise MonitorModeError(f"Could not set {name} to {target} mode: {detail or cmd}")
    proc = run("ip", "link", "set", name, "up")
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise MonitorModeError(f"{name} is in {target} mode but could not be brought up: {detail}")

    return next(i for i in interfaces() if i.name == name)


def main() -> int:  # pragma: no cover - thin CLI over the functions above
    """``python -m pps.interfaces``: print the interfaces and what each can do."""
    try:
        interfaces = list_interfaces()
    except InterfaceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for i in interfaces:
        kind = "wireless" if i.is_wireless else "loopback" if i.is_loopback else "wired/other"
        modes = "/".join(m.value for m in i.modes)
        print(f"{i.name:<16} {'up' if i.is_up else 'down':<5} {kind:<12} modes={modes}")
    problem = capture_permission_problem()
    if problem:
        print(f"note: capturing is not permitted yet: {problem}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
