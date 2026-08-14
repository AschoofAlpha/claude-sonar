"""Offline WebRTC guidance check (no network, no browser mutation).

Emits informational guidance so operators manually verify WebRTC exposure with
a known leak test. Never auto-changes browser settings. Recommendations are
optional managed-policy hardening only — no anti-detect stacks, no fingerprint
spoofing.
"""

from __future__ import annotations

from ..models import AuditCheck, Evidence

# Well-known manual leak-test sites (guidance only — this probe does not open them).
_MANUAL_LEAK_TESTS = (
    "https://browserleaks.com/webrtc",
    "https://www.ipleak.net/",
)


def check_webrtc_guidance() -> AuditCheck:
    """Emit cheap offline WebRTC hardening / manual-test guidance.

    Status is always ``unknown`` with ``info`` severity: local policy presence
    is checked elsewhere (collector); this probe does not exercise WebRTC or
    claim a pass/fail leak result.
    """
    evidence = [
        Evidence(
            type="webrtc_guidance",
            description="Manual WebRTC verification guidance (no auto-test, no settings change)",
            data={
                "auto_changed_browser_settings": False,
                "runtime_webrtc_exercised": False,
                "manual_leak_test_urls": list(_MANUAL_LEAK_TESTS),
                "policy_hardening_only": True,
                "anti_detect_recommended": False,
                "fingerprint_spoof_recommended": False,
            },
        )
    ]

    explanation = (
        "WebRTC can expose local or physical-network addresses even when HTTP(S) "
        "egress is proxied. Claude Sonar does not auto-change browser settings and "
        "does not run an in-browser WebRTC trial. Manually open a known leak-test page "
        f"({', '.join(_MANUAL_LEAK_TESTS)}) while your intended proxy/TUN path is active, "
        "and confirm that only the intended exit addresses appear. "
        "Collector-side managed-policy presence (Chrome/Edge/Firefox) is separate evidence "
        "and still does not prove runtime behavior."
    )

    recommendation = (
        "Optional policy hardening only: where your organization allows it, set a "
        "restrictive managed WebRTC IP-handling policy (for Chromium-family browsers, "
        "WebRTCIPHandling=disable_non_proxied_udp; for Firefox, a managed DisableWebRTC "
        "or equivalent enterprise policy). Prefer the browser's documented enterprise "
        "policy channel — do not install anti-detect browsers, spoof fingerprints, or "
        "run untrusted \"WebRTC killer\" extensions. Re-check with a manual leak test "
        "after any policy change. This tool will not apply those settings for you."
    )

    return AuditCheck(
        id="browser.webrtc.guidance",
        title="WebRTC manual verification guidance",
        category="browser",
        status="unknown",
        severity="info",
        confidence="unknown",
        evidence=evidence,
        explanation=explanation,
        recommendation=recommendation,
        requires_admin=False,
        remediation_available=False,
        rollback_available=False,
    )