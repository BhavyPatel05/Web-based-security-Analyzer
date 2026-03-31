"""
TCP port scanner for the target host.

Uses python-nmap against ports 1–1024 when Nmap is installed (recommended).
Open ports outside 80/443 are surfaced as findings (unnecessary services increase
attack surface). Standard web ports 80/443 are still listed in ``open_ports`` but
do not add scoring findings in the controller.

Fallback: if Nmap is unavailable or errors, probes a curated subset of ports in
the 1–1024 range via TCP connect (see ``FALLBACK_PORTS``).
"""

from __future__ import annotations

import socket

try:
    import nmap
except ImportError:
    nmap = None


def _quick_tcp_probe(host: str, port: int, timeout: float = 0.35) -> bool:
    """Single-port TCP connect probe; returns True if the port accepts connections."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except OSError:
        return False


# When Nmap is unavailable, probe these ports within 1–1024 (common services)
FALLBACK_PORTS = sorted(
    set(
        list(range(1, 11))
        + [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995]
        + list(range(512, 515))
        + [587, 631, 636, 993, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9000]
        + list(range(1000, 1025))
    )
)


def scan_common_ports(
    host: str,
    port_range: str = "1-1024",
    host_timeout: int = 120,
) -> dict:
    """
    Scan TCP ports 1–1024 using nmap when available.

    Returns:
        open_ports: sorted list of integers
        error: optional error string from nmap
        method: 'nmap' | 'socket_probe'
        note: optional explanation when using fallback
    """
    result: dict = {"open_ports": [], "error": None, "method": "nmap"}

    if not host:
        result["error"] = "Empty host"
        return result

    if nmap is not None:
        try:
            nm = nmap.PortScanner()
            nm.scan(
                host,
                port_range,
                arguments=f"-T4 --host-timeout {min(host_timeout, 90)}s",
            )
            if host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for p in sorted(nm[host][proto].keys()):
                        state = nm[host][proto][p].get("state", "")
                        if state == "open":
                            result["open_ports"].append(int(p))
            return result
        except Exception as e:
            result["error"] = str(e)
            result["method"] = "fallback"

    result["method"] = "socket_probe"
    result["note"] = (
        "Nmap not available or scan failed; probed a fallback set within 1–1024. "
        "Install Nmap and ensure python-nmap works for a full 1–1024 scan."
    )
    for p in FALLBACK_PORTS:
        if _quick_tcp_probe(host, p):
            result["open_ports"].append(p)
    result["open_ports"] = sorted(set(result["open_ports"]))
    return result
