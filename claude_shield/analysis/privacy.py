def collect_privacy_checks(data, builder):
    from .common import evidence

    claude = data.get("ClaudeCode", {})
    if not isinstance(claude, dict):
        claude = {}

    def privacy_state(values_key, active_key):
        rows = claude.get(values_key)
        if isinstance(rows, list):
            valid_rows = [item for item in rows if isinstance(item, dict)]
            present = any(item.get("Present") is True or "Value" in item for item in valid_rows)
            process_row = next(
                (item for item in valid_rows if str(item.get("Scope", "")).lower() == "process"),
                None,
            )
            if process_row is not None:
                active = process_row.get("Active") is True or str(process_row.get("Value", "")).strip() == "1"
            else:
                active = claude.get(active_key) is True or any(
                    item.get("Active") is True or str(item.get("Value", "")).strip() == "1"
                    for item in valid_rows
                )
            return active, present
        active = claude.get(active_key) is True
        return active, active

    add = builder.add
    privacy_controls = (
        ("privacy.telemetry", "Claude Code metrics telemetry", "DisableTelemetryVars", "DisableTelemetryActive", "DISABLE_TELEMETRY"),
        ("privacy.errors", "Claude Code error reporting", "DisableErrorReportingVars", "DisableErrorReportingActive", "DISABLE_ERROR_REPORTING"),
        ("privacy.nonessential", "Claude Code non-essential traffic", "DisableNonessentialTrafficVars", "DisableNonessentialTrafficActive", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"),
    )
    broad_active, _ = privacy_state("DisableNonessentialTrafficVars", "DisableNonessentialTrafficActive")
    for check_id, title, values_key, active_key, variable in privacy_controls:
        direct_active, present = privacy_state(values_key, active_key)
        active = direct_active or broad_active and variable != "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"
        explanation = (
            f"{variable}=1 is active."
            if direct_active else
            "Covered by CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1."
            if active else
            f"{variable} is present but is not set to 1."
            if present else
            f"[not_configured] {variable}=1 was not verified."
        )
        add(
            check_id,
            title,
            "privacy",
            "pass" if active else "unknown",
            "info",
            explanation,
            f"Set {variable}=1 only if that documented opt-out matches the user's privacy preference.",
        )

    supplemental_controls = (
        ("privacy.prompt_history", "Claude Code prompt-history persistence", "SkipPromptHistoryVars", "SkipPromptHistoryActive", "CLAUDE_CODE_SKIP_PROMPT_HISTORY"),
        ("privacy.subprocess_scrub", "Claude Code subprocess credential scrubbing", "SubprocessEnvScrubVars", "SubprocessEnvScrubActive", "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"),
        ("privacy.otel_user_prompts", "OpenTelemetry user-prompt content", "OtelLogUserPromptsVars", "OtelLogUserPromptsActive", "OTEL_LOG_USER_PROMPTS"),
        ("privacy.otel_tool_content", "OpenTelemetry tool content", "OtelLogToolContentVars", "OtelLogToolContentActive", "OTEL_LOG_TOOL_CONTENT"),
        ("privacy.otel_tool_details", "OpenTelemetry tool details", "OtelLogToolDetailsVars", "OtelLogToolDetailsActive", "OTEL_LOG_TOOL_DETAILS"),
        ("privacy.otel_raw_api", "OpenTelemetry raw API bodies", "OtelLogRawApiBodiesVars", "OtelLogRawApiBodiesActive", "OTEL_LOG_RAW_API_BODIES"),
    )
    for check_id, title, values_key, active_key, variable in supplemental_controls:
        active, present = privacy_state(values_key, active_key)
        if active:
            explanation = (
                f"{variable} is active; this is an observed setting, not proof of external transmission."
            )
        elif present:
            explanation = (
                f"[not_configured] {variable} is present but its enabling value was not observed."
            )
        else:
            explanation = f"[not_configured] {variable} was not observed."
        add(check_id, title, "privacy", "unknown", "info", explanation)

    # --- Local artifacts: recommend hygiene only; never claim server-side unban ---
    artifacts = claude.get("LocalArtifacts")
    if not isinstance(artifacts, list):
        artifacts = []
    present_labels = []
    for row in artifacts:
        if isinstance(row, dict) and row.get("Present") is True:
            label = str(row.get("Label") or "").strip()
            if label:
                present_labels.append(label)

    device_present = claude.get("DeviceIdArtifactPresent")
    if device_present is None:
        device_present = any(
            any(k in lab for k in ("device_id", "claude_json", "claude_home", "appdata_claude", "localappdata_claude", "anthropic"))
            for lab in present_labels
        )
    cache_present = claude.get("TelemetryCachePresent")
    if cache_present is None:
        cache_present = any(any(k in lab for k in ("statsig", "telemetry", "cache")) for lab in present_labels)

    if device_present:
        add(
            "privacy.local_device_id",
            "Local Claude/device identity artifacts",
            "privacy",
            "unknown",
            "info",
            "Local Claude-related paths are present (presence only; IDs are not read). "
            "This does not prove the account or device is marked server-side.",
            "Optional: reset local device-id/home artifacts only if you want a fresh *local* identity. "
            "This cannot clear Anthropic server-side device/account marks, cannot unban, and is not required for a healthy proxy audit. "
            "Prefer backup-then-delete of known local paths; do not use fingerprint-spoofing tools.",
            evidence=[evidence("local_artifact", "device_id_artifact_present", True)],
        )
    else:
        add(
            "privacy.local_device_id",
            "Local Claude/device identity artifacts",
            "privacy",
            "pass",
            "info",
            "No common local Claude device-id/home artifacts were observed.",
            "No local device-id reset recommended from this scan.",
        )

    if cache_present:
        add(
            "privacy.telemetry_cache",
            "Local telemetry/cache artifacts",
            "privacy",
            "unknown",
            "info",
            "Local telemetry/cache-related paths under Claude home are present (sizes only; contents not read).",
            "Optional privacy hygiene: clear local telemetry/cache directories after backup if you want less residual local data. "
            "Disabling DISABLE_TELEMETRY / related env vars matters more for future collection. "
            "Clearing cache does not remove server-side history or device marks.",
            evidence=[evidence("local_artifact", "telemetry_cache_present", True)],
        )
    else:
        add(
            "privacy.telemetry_cache",
            "Local telemetry/cache artifacts",
            "privacy",
            "pass",
            "info",
            "No common local telemetry/cache artifact paths were observed.",
            "No local cache clear recommended from this scan.",
        )

    # Browser fingerprint posture: policy-level recommendation only
    browsers = data.get("Browsers")
    if isinstance(browsers, dict) and browsers:
        any_installed = False
        any_restrictive = False
        any_unknown = False
        for _name, audit in browsers.items():
            if not isinstance(audit, dict) or audit.get("Installed") is False:
                continue
            any_installed = True
            if audit.get("RestrictiveWebRtcPolicyDetected") is True:
                any_restrictive = True
            else:
                any_unknown = True
        if any_installed:
            if any_restrictive and not any_unknown:
                add(
                    "privacy.browser_fingerprint",
                    "Browser fingerprint / WebRTC posture",
                    "privacy",
                    "pass",
                    "info",
                    "Installed browsers show restrictive WebRTC policy signals.",
                    "No fingerprint spoofing recommended. Keep policy-based WebRTC restrictions; avoid anti-detect browsers.",
                )
            else:
                add(
                    "privacy.browser_fingerprint",
                    "Browser fingerprint / WebRTC posture",
                    "privacy",
                    "unknown",
                    "info",
                    "Browser WebRTC runtime was not fully verified, or restrictive policy was not observed on all installed browsers.",
                    "Optional: tighten real browser WebRTC/privacy settings (policy or browser flags). "
                    "Do not recommend anti-detect browsers or fabricated fingerprints — they do not clear server marks and fight the product boundary. "
                    "If using Claude in browser, prefer a normal profile with proxy + WebRTC restrictions over spoofing stacks.",
                )
