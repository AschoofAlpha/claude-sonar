"""Optional DNS path observation used only when online probes are enabled.

Observation only — status is always ``unknown``. Successful resolution proves
DNS works on some path; it does not prove the path is the tunnel or exclude a leak.

Unique-label techniques (uuid + nip.io / sslip.io / similar public-suffix
echo services) are intentionally NOT used: they publish a correlatable unique
name to third-party DNS infrastructure and are unsuitable for a privacy audit.
"""

from __future__ import annotations

import socket
from typing import Iterable, List, Optional, Sequence

from ..models import AuditCheck, Evidence

# Well-known public names only. No unique/random labels under public suffixes.
DEFAULT_DNS_HOSTNAMES: Sequence[str] = (
    "one.one.one.one",
    "cloudflare.com",
)


def _resolve_one(hostname: str, timeout: float) -> dict:
    """Resolve a single hostname; never include raw addresses in the result."""
    try:
        previous = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(previous)

        families = sorted({
            "ipv6" if item[0] == socket.AF_INET6 else "ipv4"
            for item in infos
            if item and item[0] in (socket.AF_INET, socket.AF_INET6)
        })
        return {
            "hostname": hostname,
            "ok": True,
            "address_families": families,
            "record_count": len(infos),
            "raw_addresses_persisted": False,
        }
    except OSError as exc:
        return {
            "hostname": hostname,
            "ok": False,
            "error": type(exc).__name__,
            "raw_addresses_persisted": False,
        }


def check_dns_consistency(
    hostname: str = "one.one.one.one",
    timeout: float = 3,
    hostnames: Optional[Iterable[str]] = None,
) -> AuditCheck:
    """Observe whether public names resolve; do not claim leak pass/fail.

    ``hostname`` is retained for backward compatibility (single-name callers).
    Prefer ``hostnames`` for multi-name observation (default: one.one.one.one
    and cloudflare.com). Status is always informational ``unknown``.
    """
    if hostnames is not None:
        names: List[str] = [str(h).strip() for h in hostnames if str(h).strip()]
    else:
        # Keep legacy single-hostname override when caller passes hostname= only.
        if hostname and hostname != "one.one.one.one":
            names = [hostname]
        else:
            names = list(DEFAULT_DNS_HOSTNAMES)

    if not names:
        names = list(DEFAULT_DNS_HOSTNAMES)

    results = [_resolve_one(name, timeout) for name in names]
    evidence = [
        Evidence(
            type="dns_resolution",
            description="DNS resolution observation (no raw addresses stored)",
            data={
                "resolutions": results,
                "unique_label_technique": "not_used",
                "unique_label_note": (
                    "uuid+nip.io/sslip.io style unique names are intentionally avoided; "
                    "they leak a correlatable label to third-party DNS."
                ),
            },
        )
    ]

    ok_names = [r["hostname"] for r in results if r.get("ok")]
    fail_names = [r["hostname"] for r in results if not r.get("ok")]
    family_summary = {
        r["hostname"]: ",".join(r.get("address_families") or []) or "none"
        for r in results
        if r.get("ok")
    }

    parts = []
    if ok_names:
        detail = "; ".join(f"{h}→[{family_summary.get(h, 'unknown')}]" for h in ok_names)
        parts.append(f"Resolved: {detail}.")
    if fail_names:
        parts.append(f"Failed: {', '.join(fail_names)}.")
    parts.append(
        "This confirms resolution occurred or failed on the observed path; "
        "it does not prove or exclude a DNS leak. "
        "Unique-hostname public-suffix probes are not used."
    )

    return AuditCheck(
        id="network.dns.consistency",
        title="DNS resolution observation",
        category="network",
        status="unknown",
        severity="info",
        confidence="possible" if ok_names else "unknown",
        evidence=evidence,
        explanation=" ".join(parts),
    )
