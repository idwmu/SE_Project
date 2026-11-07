"""BPF capture-filter validation (PPS-F-020)."""

from __future__ import annotations


class BpfError(ValueError):
    pass


def validate_bpf(expr: str, iface: str | None = None) -> bool:
    """Compile a BPF expression with libpcap / Npcap.

    Returns True if compiled, False if no libpcap is available to check it (the capture start
    will then report any error). Raises BpfError for an invalid expression.
    """
    if not expr or not expr.strip():
        return True
    from scapy.arch.common import compile_filter

    try:
        compile_filter(expr, iface=iface)
    except ImportError:
        return False
    except Exception as exc:  # Scapy raises Scapy_Exception with libpcap's message
        raise BpfError(str(exc) or "Invalid BPF expression") from exc
    return True
