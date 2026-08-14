"""Optional lightweight public-IP reputation observation (online only).

Fetches categorical geo/ASN-style fields from a keyless public endpoint.
Never claims account safety. Raw IPs are redacted before they enter checks.
"""

from __future__ import annotations

import json
import ipaddress
from typing import Any, Dict, Optional, Tuple

from ..models import AuditCheck, Evidence
from ..redaction import Redactor
from .base import ProbeError
from .egress import extract_ip
from .http_probe import fetch_http
from .runtime_probe import run_python_probe

# Keyless, short-timeout sources. First success wins.
_REPUTATION_SOURCES = (
    "https://ipapi.co/json/",
    "https://ipinfo.io/json",
)

# Fallbacks used only to obtain an egress token when reputation JSON has no IP.
_EGRESS_FALLBACKS = (
    "https://api.ipify.org",
    "https://1.1.1.1/cdn-cgi/trace",
)


def _redact_ip(redactor: Redactor, ip_str: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (redacted_token, address_family) or (None, None) if invalid."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None, None
    if ip.version == 6:
        return redactor.redact_ipv6(str(ip)), "ipv6"
    return redactor.redact_ipv4(str(ip)), "ipv4"


def _normalize_country(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().upper()
    if len(text) == 2 and text.isalpha():
        return text
    return None


def _normalize_asn(payload: Dict[str, Any]) -> Optional[str]:
    """Return a categorical ASN label like AS13335, never a free-form blob."""
    for key in ("asn", "as", "org"):
        raw = payload.get(key)
        if raw is None:
            continue
        text = str(raw).strip()
        # ipinfo: "AS15169 Google LLC" — take leading ASnnnn
        if text.upper().startswith("AS"):
            token = text.split()[0]
            digits = token[2:]
            if digits.isdigit():
                return f"AS{digits}"
        # ipapi: separate asn field "AS15169"
        if key == "asn" and text:
            cleaned = text.upper().replace(" ", "")
            if cleaned.startswith("AS") and cleaned[2:].isdigit():
                return cleaned
            if text.isdigit():
                return f"AS{text}"
    return None


def _normalize_org(payload: Dict[str, Any]) -> Optional[str]:
    """Provider/org label only — categorical, no IP material."""
    for key in ("org", "org_name", "organization", "isp"):
        raw = payload.get(key)
        if not raw:
            continue
        text = str(raw).strip()
        # ipinfo packs "AS15169 Google LLC" into org — strip leading ASN token
        parts = text.split()
        if parts and parts[0].upper().startswith("AS") and parts[0][2:].isdigit():
            text = " ".join(parts[1:]).strip()
        if text:
            # Bound length; avoid dumping huge free-text fields
            return text[:120]
    return None


def _parse_reputation_json(text: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _fetch_reputation_payload(timeout: int) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """Return (payload, source_id, error_name)."""
    last_error = None
    for url in _REPUTATION_SOURCES:
        try:
            body, _mode = fetch_http(url, timeout=timeout, max_bytes=8192)
            data = _parse_reputation_json(body)
            if not data:
                last_error = "invalid_json"
                continue
            # Prefer sources that at least expose a country-like field or an IP.
            if not any(k in data for k in ("country", "country_code", "countryCode", "ip")):
                last_error = "missing_fields"
                continue
            source_id = "ipapi.co" if "ipapi.co" in url else "ipinfo.io"
            return data, source_id, None
        except ProbeError as exc:
            last_error = type(exc).__name__
        except Exception as exc:  # noqa: BLE001 — best-effort online probe
            last_error = type(exc).__name__
    return None, None, last_error or "unavailable"


def _fetch_egress_token(redactor: Redactor, timeout: int) -> Tuple[Optional[str], Optional[str]]:
    """Best-effort public egress IP via known observation endpoints."""
    for url in _EGRESS_FALLBACKS:
        try:
            result = run_python_probe(url, timeout=timeout, is_custom=False)
            if not result or not result[0]:
                continue
            ip_str = extract_ip(result[0])
            if not ip_str:
                continue
            return _redact_ip(redactor, ip_str)
        except Exception:  # noqa: BLE001
            continue
    return None, None


def check_ip_reputation(
    timeout: int = 5,
    intended_region: Optional[str] = None,
    redactor: Optional[Redactor] = None,
) -> AuditCheck:
    """Observe categorical exit geo/ASN fields. Status is pass or unknown only.

    Never claims account safety, eligibility, or that a route is "clean".
    ``intended_region`` is an optional ISO-3166-1 alpha-2 code used only for
    a soft consistency note; mismatch stays ``unknown``, never fail/warning.
    """
    redactor = redactor or Redactor()
    evidence = []

    payload, source_id, err = _fetch_reputation_payload(timeout)

    if not payload:
        evidence.append(Evidence(
            type="ip_reputation",
            description="Reputation lookup unavailable",
            data={"error": err or "unavailable", "raw_value_persisted": False},
        ))
        return AuditCheck(
            id="network.ip_reputation",
            title="Public IP reputation observation",
            category="network",
            status="unknown",
            severity="info",
            confidence="unknown",
            evidence=evidence,
            explanation=(
                "Lightweight public IP reputation lookup did not return usable data. "
                "Treat as incomplete evidence — not as a safety pass or account risk."
            ),
        )

    # Country: accept several vendor field names
    country = (
        _normalize_country(payload.get("country_code"))
        or _normalize_country(payload.get("countryCode"))
        or _normalize_country(payload.get("country"))
    )
    asn = _normalize_asn(payload)
    org = _normalize_org(payload)

    # IP from payload (redacted) or egress fallback
    raw_ip = payload.get("ip") or payload.get("query")
    redacted_ip, family = (None, None)
    if isinstance(raw_ip, str) and raw_ip.strip():
        redacted_ip, family = _redact_ip(redactor, raw_ip)
    if not redacted_ip:
        redacted_ip, family = _fetch_egress_token(redactor, timeout)

    categorical = {
        "source": source_id,
        "country_code": country,
        "asn": asn,
        "org": org,
        "address_family": family,
        "observed_address": redacted_ip,
        "raw_value_persisted": False,
    }
    # Drop empty optional keys for cleaner evidence
    categorical = {k: v for k, v in categorical.items() if v is not None or k == "raw_value_persisted"}

    evidence.append(Evidence(
        type="ip_reputation",
        description="Categorical public-IP reputation fields",
        data=categorical,
    ))

    intended = _normalize_country(intended_region) if intended_region else None
    region_note = ""
    status = "pass"
    confidence = "possible"

    if intended and country:
        if intended == country:
            region_note = f" Observed country code matches intended region {intended}."
        else:
            # Soft inconsistency only — reputation never emits warning/fail.
            status = "unknown"
            confidence = "possible"
            region_note = (
                f" Observed country code differs from intended region {intended}. "
                "This is a routing-consistency note only, not an account-safety signal."
            )
    elif intended and not country:
        status = "unknown"
        confidence = "unknown"
        region_note = " Intended region was supplied but no country code was returned."

    # Build explanation without any raw IP literals
    parts = ["Lightweight reputation observation succeeded"]
    if source_id:
        parts[0] += f" via {source_id}"
    parts[0] += "."
    if country:
        parts.append(f"Country code: {country}.")
    if asn:
        parts.append(f"ASN: {asn}.")
    if org:
        parts.append(f"Org/provider label present (categorical).")
    if redacted_ip:
        parts.append(f"Egress token: {redacted_ip}.")
    parts.append(
        "These are vendor database opinions and routing labels only — "
        "not proof of account safety, eligibility, residential status, or abuse risk."
    )
    if region_note:
        parts.append(region_note.strip())

    return AuditCheck(
        id="network.ip_reputation",
        title="Public IP reputation observation",
        category="network",
        status=status,
        severity="info",
        confidence=confidence,
        evidence=evidence,
        explanation=" ".join(parts),
    )
