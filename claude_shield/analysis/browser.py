def collect_browser_checks(data, builder):
    browsers = data.get("Browsers")
    if not isinstance(browsers, dict):
        return
    add = builder.add
    for browser, audit in browsers.items():
        if not isinstance(audit, dict) or audit.get("Installed") is False:
            continue
        restricted = audit.get("RestrictiveWebRtcPolicyDetected")
        add(
            f"browser.webrtc.{str(browser).lower()}",
            f"{browser} WebRTC policy",
            "browser",
            "pass" if restricted is True else "unknown",
            "info",
            "A restrictive WebRTC policy is configured."
            if restricted is True
            else "WebRTC runtime behavior was not verified; browser settings alone do not prove a leak.",
            "",
        )
