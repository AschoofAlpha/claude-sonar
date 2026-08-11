def collect_browser_checks(data, builder):
    browsers = data.get("Browsers")
    if not isinstance(browsers, dict):
        return
    add = builder.add
    for browser, audit in browsers.items():
        if not isinstance(audit, dict) or audit.get("Installed") is False:
            continue
        restricted = audit.get("RestrictiveWebRtcPolicyDetected")
        if restricted is True:
            explanation = (
                "A restrictive WebRTC policy is configured (policy-layer signal only; "
                "not a live page WebRTC test)."
            )
            recommendation = (
                "Optional policy only: keep the restrictive WebRTC policy if it matches "
                "your privacy preference. Do not install anti-detect browsers or spoof "
                "fingerprints. This tool never changes browser settings automatically."
            )
            status = "pass"
        else:
            explanation = (
                "WebRTC runtime behavior was not verified; browser settings alone do not "
                "prove a leak. Policy presence is informational only."
            )
            recommendation = (
                "Optional recommendation only (never auto-applied): if you want less local "
                "address exposure, tighten real-browser WebRTC/privacy policy or flags. "
                "Do not use anti-detect stacks or fabricated fingerprints. "
                "Claude Shield will not change DNS, routes, TUN, timezone, or fingerprints for you."
            )
            status = "unknown"
        add(
            f"browser.webrtc.{str(browser).lower()}",
            f"{browser} WebRTC policy",
            "browser",
            status,
            "info",
            explanation,
            recommendation,
        )
