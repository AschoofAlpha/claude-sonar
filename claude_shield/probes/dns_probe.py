"""Optional DNS path observation used only when online probes are enabled.

Observation only — status is always ``unknown``. Successful resolution proves
DNS works on some path; it does not prove the path is the tunnel or exclude a leak.

Unique-label techniques (uuid + nip.io / sslip.io / similar public-suffix
echo services) are intentionally NOT used: they publish a correlatable unique
name to third-party DNS infrastructure and are unsuitable for a privacy audit.

When ``online=True``, multiple observation methods are used (any / IPv4-only /
IPv6-only system lookups). Outcomes are classified by family class — raw
resolver and answer IPs are never persisted.
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

# Online multi-method observation labels (no third-party DoH; system resolver only).
_ONLINE_METHODS: Sequence[str] = (
    "system_any",
    "system_ipv4",
    "system_ipv6",
)


def _family_class(families: Sequence[str]) -> str:
    """Classify observed address families without exposing raw addresses."""
    fams = {f for f in families if f in ("ipv4", "ipv6")}
    if fams == {"ipv4", "ipv6"}:
        return "dual_stack"
    if fams == {"ipv4"}:
        return "ipv4_only"
    if fams == {"ipv6"}:
        return "ipv6_only"
    if not fams:
        return "empty"
    return "unknown"


def _outcome_class(*, ok: bool, families: Sequence[str], error: Optional[str] = None) -> str:
    if not ok:
        err = (error or "").lower()
        if "timeout" in err:
            return "timeout"
        return "resolution_failed"
    return _family_class(families)


def _resolve_one(
    hostname: str,
    timeout: float,
    *,
    method: str = "system_any",
) -> dict:
    """Resolve a single hostname with a named method; never include raw addresses."""
    family_filter = None
    if method == "system_ipv4":
        family_filter = socket.AF_INET
    elif method == "system_ipv6":
        family_filter = socket.AF_INET6
    elif method != "system_any":
        return {
            "hostname": hostname,
            "method": method,
            "ok": False,
            "outcome_class": "unsupported_method",
            "error": "unsupported_method",
            "raw_addresses_persisted": False,
        }

    try:
        previous = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            if family_filter is None:
                infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
            else:
                infos = socket.getaddrinfo(
                    hostname, 443, family_filter, type=socket.SOCK_STREAM
                )
        finally:
            socket.setdefaulttimeout(previous)

        families = sorted({
            "ipv6" if item[0] == socket.AF_INET6 else "ipv4"
            for item in infos
            if item and item[0] in (socket.AF_INET, socket.AF_INET6)
        })
        outcome = _outcome_class(ok=True, families=families)
        return {
            "hostname": hostname,
            "method": method,
            "ok": True,
            "address_families": families,
            "family_class": _family_class(families),
            "outcome_class": outcome,
            "record_count": len(infos),
            "raw_addresses_persisted": False,
        }
    except OSError as exc:
        err_name = type(exc).__name__
        return {
            "hostname": hostname,
            "method": method,
            "ok": False,
            "outcome_class": _outcome_class(ok=False, families=[], error=err_name),
            "error": err_name,
            "raw_addresses_persisted": False,
        }


def check_dns_consistency(
    hostname: str = "one.one.one.one",
    timeout: float = 3,
    hostnames: Optional[Iterable[str]] = None,
    *,
    online: bool = False,
    methods: Optional[Iterable[str]] = None,
) -> AuditCheck:
    """Observe whether public names resolve; do not claim leak pass/fail.

    ``hostname`` is retained for backward compatibility (single-name callers).
    Prefer ``hostnames`` for multi-name observation (default: one.one.one.one
    and cloudflare.com). Status is always informational ``unknown``.

    When ``online=True``, multiple system-resolver methods are exercised
    (any / IPv4-only / IPv6-only) unless ``methods`` overrides the set.
    Offline / default path keeps a single ``system_any`` method per name.
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

    if methods is not None:
        method_list: List[str] = [str(m).strip() for m in methods if str(m).strip()]
    elif online:
        method_list = list(_ONLINE_METHODS)
    else:
        method_list = ["system_any"]

    if not method_list:
        method_list = ["system_any"]

    results = []
    for name in names:
        for method in method_list:
            results.append(_resolve_one(name, timeout, method=method))

    # Aggregate classes (no raw IPs).
    outcome_classes = sorted({r.get("outcome_class") or "unknown" for r in results})
    method_summary = {}
    for r in results:
        key = f"{r.get('hostname')}|{r.get('method')}"
        method_summary[key] = r.get("outcome_class") or "unknown"

    evidence = [
        Evidence(
            type="dns_resolution",
            description="DNS resolution observation (no raw addresses stored)",
            data={
                "resolutions": results,
                "methods": method_list,
                "online_multi_method": bool(online) or len(method_list) > 1,
                "outcome_classes": outcome_classes,
                "unique_label_technique": "not_used",
                "unique_label_note": (
                    "uuid+nip.io/sslip.io style unique names are intentionally avoided; "
                    "they leak a correlatable label to third-party DNS."
                ),
            },
        )
    ]

    ok_rows = [r for r in results if r.get("ok")]
    fail_rows = [r for r in results if not r.get("ok")]

    parts = []
    if ok_rows:
        detail_bits = []
        for r in ok_rows:
            fam = ",".join(r.get("address_families") or []) or "none"
            cls = r.get("family_class") or r.get("outcome_class") or "unknown"
            detail_bits.append(
                f"{r.get('hostname')}@{r.get('method')}→[{fam}|class={cls}]"
            )
        parts.append(f"Resolved: {'; '.join(detail_bits)}.")
    if fail_rows:
        fail_bits = [
            f"{r.get('hostname')}@{r.get('method')}({r.get('outcome_class') or 'failed'})"
            for r in fail_rows
        ]
        parts.append(f"Failed: {', '.join(fail_bits)}.")
    if len(outcome_classes) > 1:
        parts.append(
            f"Outcome classes observed: {', '.join(outcome_classes)} "
            "(multi-method classification only)."
        )
    parts.append(
        "This confirms resolution occurred or failed on the observed path; "
        "it does not prove or exclude a DNS leak. "
        "Unique-hostname public-suffix probes are not used. "
        "Raw resolver and answer addresses are not stored."
    )

    return AuditCheck(
        id="network.dns.consistency",
        title="DNS resolution observation",
        category="network",
        status="unknown",
        severity="info",
        confidence="possible" if ok_rows else "unknown",
        evidence=evidence,
        explanation=" ".join(parts),
    )
