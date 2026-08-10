import ipaddress
from dataclasses import replace

from ..models import AuditCheck
from ..redaction import Redactor


class CheckBuilder:
    """Accumulate AuditCheck rows with shared confidence rules."""

    def __init__(self, include_recommendations=False):
        self.include_recommendations = include_recommendations
        self.checks = []

    def add(self, check_id, title, category, status, severity, explanation, recommendation=""):
        self.checks.append(AuditCheck(
            id=check_id,
            title=title,
            category=category,
            status=status,
            severity=severity,
            confidence=(
                "probable" if status == "warning"
                else "confirmed" if status in ("pass", "fail")
                else "unknown"
            ),
            explanation=explanation,
            recommendation=recommendation if self.include_recommendations else "",
        ))


def is_local_or_fake_dns(server):
    try:
        address = ipaddress.ip_address(str(server))
        return address.is_loopback or address in ipaddress.ip_network("198.18.0.0/15")
    except ValueError:
        return False


def mihomo_protects_dns(data):
    mihomo = data.get("Mihomo")
    return (
        isinstance(mihomo, dict)
        and mihomo.get("DnsEnabled") is True
        and str(mihomo.get("DnsMode", "")).lower() == "fake-ip"
        and mihomo.get("DnsHijackAny53") is True
    )


def redact_checks(checks, redactor=None):
    redactor = redactor or Redactor()
    return [
        replace(
            check,
            title=redactor.scan_and_redact(check.title),
            explanation=redactor.scan_and_redact(check.explanation),
            recommendation=redactor.scan_and_redact(check.recommendation),
            evidence=[
                replace(
                    item,
                    description=redactor.scan_and_redact(item.description),
                    data=redactor.scan_and_redact(item.data),
                )
                for item in check.evidence
            ],
        )
        for check in checks
    ]
