"""Runtime egress observation and dual-stack (IPv4/IPv6) family checks."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Optional, Tuple

from ..models import AuditCheck, Evidence
from ..redaction import Redactor
from .base import ProbeContext
from .runtime_probe import run_curl_probe, run_python_probe

# Family-specific public observers (keyless, short responses).
_IPV4_EGRESS_URL = "https://api.ipify.org"
_IPV6_EGRESS_URL = "https://api6.ipify.org"


def extract_ip(text: str):
    # Prefer Cloudflare-style ip= lines, then fall back to the first IPv4/IPv6 literal.
    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ipv6_pattern = r"([0-9a-fA-F]{1,4}:){1,7}:?[0-9a-fA-F]{1,4}"

    # Check trace format (Cloudflare)
    for line in text.splitlines():
        if line.startswith("ip="):
            return line.split("=", 1)[1].strip()

    # Check plain IP
    m4 = re.search(ipv4_pattern, text)
    if m4:
        return m4.group(0)

    m6 = re.search(ipv6_pattern, text)
    if m6:
        return m6.group(0)

    return None


def _redact_observation(redactor: Redactor, ip_str: str) -> Optional[Dict[str, Any]]:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None
    if ip.version == 6:
        return {
            "address_family": "ipv6",
            "observed_address": redactor.redact_ipv6(str(ip)),
            "raw_value_persisted": False,
        }
    return {
        "address_family": "ipv4",
        "observed_address": redactor.redact_ipv4(str(ip)),
        "raw_value_persisted": False,
    }


def observe_egress_url(
    url: str,
    timeout: int = 5,
    *,
    redactor: Optional[Redactor] = None,
    is_custom: bool = False,
    expected_family: Optional[str] = None,
) -> Dict[str, Any]:
    """Best-effort single-URL egress observation with redacted token only."""
    redactor = redactor or Redactor()
    py_text = run_python_probe(url, timeout, is_custom=is_custom)
    if not py_text or not py_text[0]:
        return {
            "ok": False,
            "url_class": expected_family or "any",
            "error": "unavailable",
            "raw_value_persisted": False,
        }
    text, ssrf_mode = py_text
    ip_str = extract_ip(text)
    if not ip_str:
        return {
            "ok": False,
            "url_class": expected_family or "any",
            "error": "no_ip_extracted",
            "ssrf_validation_mode": ssrf_mode,
            "raw_value_persisted": False,
        }
    obs = _redact_observation(redactor, ip_str)
    if not obs:
        return {
            "ok": False,
            "url_class": expected_family or "any",
            "error": "invalid_ip",
            "ssrf_validation_mode": ssrf_mode,
            "raw_value_persisted": False,
        }
    family = obs["address_family"]
    # If caller expected a specific family and got the other, mark mismatch class.
    family_match = True
    if expected_family and family != expected_family:
        family_match = False
    return {
        "ok": True,
        "url_class": expected_family or "any",
        "family_match_expected": family_match,
        "ssrf_validation_mode": ssrf_mode,
        **obs,
    }


def _reputation_classes(timeout: int) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Lazy-import reputation helpers; return (country, asn, source_error)."""
    try:
        # Import inside function to avoid circular import at module load
        # (reputation imports extract_ip from this module).
        from .reputation import (  # noqa: WPS433
            _fetch_reputation_payload,
            _normalize_asn,
            _normalize_country,
        )
    except Exception:  # noqa: BLE001
        return None, None, "reputation_import_unavailable"

    try:
        payload, _source_id, err = _fetch_reputation_payload(timeout)
    except Exception as exc:  # noqa: BLE001
        return None, None, type(exc).__name__

    if not payload:
        return None, None, err or "unavailable"

    country = (
        _normalize_country(payload.get("country_code"))
        or _normalize_country(payload.get("countryCode"))
        or _normalize_country(payload.get("country"))
    )
    asn = _normalize_asn(payload)
    return country, asn, None


def check_egress_consistency(ctx: ProbeContext, is_custom: bool = False, redactor: Optional[Redactor] = None):
    # Compare Python stdlib and curl egress when both are available.
    # Shared redactor (caller-provided) keeps tokens comparable across endpoints.

    # Python stdlib
    py_text = run_python_probe(ctx.endpoint.url, ctx.timeout, is_custom=is_custom)
    # curl stdlib
    curl_text = run_curl_probe(ctx.endpoint.url, ctx.timeout)

    # Memory-only IP pseudonymization; raw addresses are not persisted.
    redactor = redactor or Redactor()

    def process_result(runtime, probe_result):
        if not probe_result:
            return None, "unavailable"
        text, ssrf_mode = probe_result
        if not text:
            return None, ssrf_mode
        ip_str = extract_ip(text)
        if not ip_str:
            return None, ssrf_mode

        try:
            ip = ipaddress.ip_address(ip_str)
            # Memory-only redaction
            return {
                "runtime": runtime,
                "endpoint": ctx.endpoint.id,
                "address_family": "ipv6" if ip.version == 6 else "ipv4",
                "observed_address": redactor.redact_ipv6(ip_str)
                if ip.version == 6
                else redactor.redact_ipv4(ip_str),
                "raw_value_persisted": False,
            }, ssrf_mode
        except ValueError:
            return None, ssrf_mode

    ev_py, ssrf_py = process_result("python", py_text)
    ev_curl, ssrf_curl = process_result("curl", curl_text)

    evidence = []
    if ev_py:
        ev_py["ssrf_validation_mode"] = ssrf_py
        evidence.append(Evidence(type="runtime_egress", description="Python egress", data=ev_py))
    if ev_curl:
        ev_curl["ssrf_validation_mode"] = ssrf_curl
        evidence.append(Evidence(type="runtime_egress", description="Curl egress", data=ev_curl))

    status = "unknown"
    confidence = "unknown"
    explanation = "Only one probe source succeeded or none succeeded."

    if ev_py and ev_curl:
        if ev_py["observed_address"] == ev_curl["observed_address"]:
            status = "pass"
            confidence = "confirmed"
            explanation = "Egress IPs match across runtimes."
        else:
            status = "warning"
            confidence = "possible"
            explanation = (
                "Egress IPs differ across runtimes. This could be due to split routing, "
                "load balancing, or different proxy behaviors."
            )

    # Proxy Metadata Check
    from .proxy_detector import detect_proxy_for_url

    proxy_meta = detect_proxy_for_url(ctx.endpoint.url)
    proxy_evidence = Evidence(type="proxy_metadata", description="Proxy observation", data=proxy_meta)

    return AuditCheck(
        id=f"network.egress.runtime_consistency.{ctx.endpoint.id}",
        title=f"Runtime egress consistency ({ctx.endpoint.id})",
        category="network",
        status=status,
        severity="info" if status == "pass" else "medium",
        confidence=confidence,
        evidence=evidence + [proxy_evidence],
        explanation=explanation,
    )


def check_dual_stack_egress(
    timeout: int = 5,
    *,
    redactor: Optional[Redactor] = None,
    ipv4_url: str = _IPV4_EGRESS_URL,
    ipv6_url: str = _IPV6_EGRESS_URL,
) -> AuditCheck:
    """Observe IPv4 and IPv6 egress separately when possible.

    Missing IPv6 is ``unknown`` for that family — never fail. Optional
    country/ASN class labels are attached via reputation helpers when available
    (categorical only; not an account-safety signal).
    """
    redactor = redactor or Redactor()
    # Split budget roughly across both family checks + optional class lookup.
    per = max(1, int(timeout) // 2) if timeout and timeout > 1 else max(1, int(timeout) or 1)

    v4 = observe_egress_url(
        ipv4_url, timeout=per, redactor=redactor, expected_family="ipv4"
    )
    v6 = observe_egress_url(
        ipv6_url, timeout=per, redactor=redactor, expected_family="ipv6"
    )

    # Reputation classes for the default egress path (not forced per-family).
    country, asn, rep_err = _reputation_classes(max(1, per))

    families_seen = []
    if v4.get("ok") and v4.get("address_family") == "ipv4":
        families_seen.append("ipv4")
    if v6.get("ok") and v6.get("address_family") == "ipv6":
        families_seen.append("ipv6")

    evidence_data: Dict[str, Any] = {
        "ipv4": {k: v for k, v in v4.items() if k != "url"},
        "ipv6": {k: v for k, v in v6.items() if k != "url"},
        "families_observed": families_seen,
        "country_class": country,
        "asn_class": asn,
        "raw_value_persisted": False,
    }
    if rep_err and not country and not asn:
        evidence_data["reputation_class_error"] = rep_err

    evidence = [
        Evidence(
            type="dual_stack_egress",
            description="IPv4/IPv6 egress observation (redacted tokens + class labels)",
            data=evidence_data,
        )
    ]

    v4_ok = "ipv4" in families_seen
    v6_ok = "ipv6" in families_seen

    parts = []
    if v4_ok:
        parts.append(f"IPv4 egress observed (token {v4.get('observed_address')}).")
    else:
        parts.append("IPv4 egress not observed.")
    if v6_ok:
        parts.append(f"IPv6 egress observed (token {v6.get('observed_address')}).")
    else:
        parts.append(
            "IPv6 egress unavailable or not returned — treated as unknown, not a failure."
        )

    if country:
        parts.append(f"Country class (default path): {country}.")
    if asn:
        parts.append(f"ASN class (default path): {asn}.")
    parts.append(
        "Family observations and vendor class labels only — not proof of leak, "
        "account safety, or ban risk."
    )

    if v4_ok and v6_ok:
        status = "pass"
        confidence = "possible"
        severity = "info"
    elif v4_ok or v6_ok:
        # Partial dual-stack is incomplete evidence.
        status = "unknown"
        confidence = "possible"
        severity = "info"
    else:
        status = "unknown"
        confidence = "unknown"
        severity = "info"

    return AuditCheck(
        id="network.egress.dual_stack",
        title="Dual-stack egress observation (IPv4/IPv6)",
        category="network",
        status=status,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        explanation=" ".join(parts),
    )
