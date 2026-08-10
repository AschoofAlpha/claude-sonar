"""Snapshot analysis helpers split by category."""

from .browser import collect_browser_checks
from .common import CheckBuilder, is_local_or_fake_dns, mihomo_protects_dns, redact_checks
from .mihomo import collect_mihomo_checks
from .privacy import collect_privacy_checks
from .system import collect_system_checks

__all__ = [
    "CheckBuilder",
    "collect_privacy_checks",
    "collect_system_checks",
    "collect_browser_checks",
    "collect_mihomo_checks",
    "is_local_or_fake_dns",
    "mihomo_protects_dns",
    "redact_checks",
]
