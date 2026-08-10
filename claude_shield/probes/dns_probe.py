"""Optional DNS path observation used only when online probes are enabled."""

from __future__ import annotations

import socket

from ..models import AuditCheck, Evidence


def check_dns_consistency(hostname="one.one.one.one", timeout=3):
    """Observe whether a public name resolves; do not claim leak pass/fail.

    Returns an AuditCheck that is informational only. A successful resolve
    proves DNS works on some path; it does not prove the path is the tunnel.
    """
    evidence = []
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        families = sorted({
            "ipv6" if item[0] == socket.AF_INET6 else "ipv4"
            for item in infos
            if item and item[0] in (socket.AF_INET, socket.AF_INET6)
        })
        evidence.append(Evidence(
            type="dns_resolution",
            description=f"Resolved {hostname}",
            data={"hostname": hostname, "address_families": families, "record_count": len(infos)},
        ))
        return AuditCheck(
            id="network.dns.consistency",
            title="DNS resolution observation",
            category="network",
            status="unknown",
            severity="info",
            confidence="possible",
            evidence=evidence,
            explanation=(
                f"Name {hostname} resolved via address families {', '.join(families) or 'unknown'}. "
                "This confirms resolution occurred; it does not prove or exclude a DNS leak."
            ),
        )
    except OSError as exc:
        evidence.append(Evidence(
            type="dns_resolution",
            description=f"Failed to resolve {hostname}",
            data={"hostname": hostname, "error": type(exc).__name__},
        ))
        return AuditCheck(
            id="network.dns.consistency",
            title="DNS resolution observation",
            category="network",
            status="unknown",
            severity="info",
            confidence="unknown",
            evidence=evidence,
            explanation=(
                f"Name {hostname} could not be resolved ({type(exc).__name__}). "
                "Treat as incomplete evidence, not as a confirmed leak or pass."
            ),
        )
