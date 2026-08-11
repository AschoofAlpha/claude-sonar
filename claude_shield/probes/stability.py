"""Egress stability sampling (online only).

Samples categorical egress class labels twice with a short delay. A change in
country/ASN class between samples is a routing-consistency warning — never a
ban-risk claim.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, Tuple

from ..models import AuditCheck, Evidence
from ..redaction import Redactor


def _sample_classes(timeout: int, redactor: Redactor) -> Dict[str, Any]:
    """One categorical sample via reputation helpers (lazy import)."""
    try:
        from .reputation import (  # noqa: WPS433 — avoid circular import at load
            _fetch_egress_token,
            _fetch_reputation_payload,
            _normalize_asn,
            _normalize_country,
            _redact_ip,
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "error": f"import:{type(exc).__name__}",
            "country_class": None,
            "asn_class": None,
            "raw_value_persisted": False,
        }

    try:
        payload, source_id, err = _fetch_reputation_payload(timeout)
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "error": type(exc).__name__,
            "country_class": None,
            "asn_class": None,
            "raw_value_persisted": False,
        }

    if not payload:
        # Fall back to egress token alone (no country/asn).
        token, family = _fetch_egress_token(redactor, timeout)
        return {
            "ok": bool(token),
            "error": err or ("no_token" if not token else None),
            "country_class": None,
            "asn_class": None,
            "address_family": family,
            "observed_address": token,
            "source": None,
            "raw_value_persisted": False,
        }

    country = (
        _normalize_country(payload.get("country_code"))
        or _normalize_country(payload.get("countryCode"))
        or _normalize_country(payload.get("country"))
    )
    asn = _normalize_asn(payload)

    raw_ip = payload.get("ip") or payload.get("query")
    redacted_ip, family = None, None
    if isinstance(raw_ip, str) and raw_ip.strip():
        redacted_ip, family = _redact_ip(redactor, raw_ip)
    if not redacted_ip:
        redacted_ip, family = _fetch_egress_token(redactor, timeout)

    return {
        "ok": bool(country or asn or redacted_ip),
        "error": None,
        "country_class": country,
        "asn_class": asn,
        "address_family": family,
        "observed_address": redacted_ip,
        "source": source_id,
        "raw_value_persisted": False,
    }


def _class_key(sample: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Comparable (country, asn) key; None if insufficient class data."""
    country = sample.get("country_class")
    asn = sample.get("asn_class")
    if not country and not asn:
        return None
    return (str(country or ""), str(asn or ""))


def check_egress_stability(
    timeout: int = 5,
    *,
    samples: int = 2,
    delay_s: float = 0.4,
    redactor: Optional[Redactor] = None,
    sleeper=None,
) -> AuditCheck:
    """Sample egress country/ASN classes twice; warn only on class change.

    Respects ``timeout`` as a rough total budget. Does not claim ban risk,
    account safety, or that a stable path is \"clean\".
    """
    redactor = redactor or Redactor()
    sleeper = sleeper or time.sleep
    n = max(2, int(samples) or 2)
    # Budget: leave a little room for delay; split remaining across samples.
    delay = max(0.0, min(float(delay_s), max(0.0, float(timeout) * 0.25)))
    usable = max(1.0, float(timeout) - delay * (n - 1))
    per = max(1, int(usable // n))

    collected = []
    for i in range(n):
        collected.append(_sample_classes(per, redactor))
        if i < n - 1 and delay > 0:
            try:
                sleeper(delay)
            except Exception:  # noqa: BLE001
                pass

    evidence = [
        Evidence(
            type="egress_stability",
            description="Multi-sample egress class observation",
            data={
                "samples": collected,
                "sample_count": len(collected),
                "delay_s": delay,
                "raw_value_persisted": False,
            },
        )
    ]

    keys = [_class_key(s) for s in collected]
    usable_keys = [k for k in keys if k is not None]

    if len(usable_keys) < 2:
        return AuditCheck(
            id="network.egress.stability",
            title="Egress class stability",
            category="network",
            status="unknown",
            severity="info",
            confidence="unknown",
            evidence=evidence,
            explanation=(
                "Fewer than two samples returned comparable country/ASN class labels. "
                "Treat as incomplete routing evidence — not as stability pass or ban risk."
            ),
        )

    unique = set(usable_keys)
    if len(unique) == 1:
        country, asn = usable_keys[0]
        label_bits = []
        if country:
            label_bits.append(f"country={country}")
        if asn:
            label_bits.append(f"asn={asn}")
        label = ", ".join(label_bits) or "class present"
        return AuditCheck(
            id="network.egress.stability",
            title="Egress class stability",
            category="network",
            status="pass",
            severity="info",
            confidence="possible",
            evidence=evidence,
            explanation=(
                f"Country/ASN class labels were stable across {len(usable_keys)} samples "
                f"({label}). This is a short-window routing consistency note only — "
                "not proof of long-term stability, account safety, or ban risk."
            ),
        )

    return AuditCheck(
        id="network.egress.stability",
        title="Egress class stability",
        category="network",
        status="warning",
        severity="medium",
        confidence="possible",
        evidence=evidence,
        explanation=(
            f"Country/ASN class labels changed across {len(usable_keys)} short-window samples "
            f"({len(unique)} distinct class tuples). This may indicate exit hopping, "
            "load balancing, or multi-path routing — a consistency warning only, "
            "not a ban-risk or account-safety claim."
        ),
    )
