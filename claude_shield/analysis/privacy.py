def collect_privacy_checks(data, builder):
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
            f"{variable}=1 was not verified."
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
        explanation = (
            f"{variable} is active; this is an observed setting, not proof of external transmission."
            if active else
            f"{variable} is present but its enabling value was not observed."
            if present else
            f"{variable} was not observed."
        )
        add(check_id, title, "privacy", "unknown", "info", explanation)
