"""Collector analysis for Claude Shield (AI-facing library).

Runs the read-only collector and turns the snapshot into structured audit
checks. Intended to be imported by an agent skill (Codex / Claude Code),
not invoked as a CLI. No output rendering lives here; agents format the
checks themselves per SKILL.md's Report Format.
"""

import json
import os
import shutil
import subprocess
from dataclasses import replace

from .models import AuditCheck
from .redaction import Redactor
from .resources import resource_path


class CollectorError(RuntimeError):
    """Raised when the platform collector fails."""


def run_legacy_collector(timeout=30):
    """Run the platform collector and return its parsed JSON snapshot.

    Raises CollectorError on missing runtime, non-zero exit, timeout, or
    unparseable output. Never prints or exits the process.
    """
    try:
        if os.name == "nt":
            script_path = resource_path("scripts", "collect_windows_network.ps1")
            executable = shutil.which("pwsh") or shutil.which("powershell.exe")
            if not executable:
                raise CollectorError("PowerShell is not available.")
            command = [
                executable,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
            ]
        else:
            script_path = resource_path("scripts", "collect_posix_network.sh")
            executable = shutil.which("bash")
            if not executable:
                raise CollectorError("bash is not available.")
            command = [executable, str(script_path)]

        result = subprocess.run(command, capture_output=True, timeout=timeout)
        if result.returncode != 0:
            error = Redactor().scan_and_redact(result.stderr.decode("utf-8", errors="replace").strip())
            raise CollectorError(f"collector exited with code {result.returncode}: {error}")
        stdout = result.stdout.decode("utf-8-sig", errors="replace")
        start = stdout.find("{")
        if start < 0:
            raise CollectorError("collector returned no JSON object")
        return json.loads(stdout[start:])
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        raise CollectorError(Redactor().scan_and_redact(str(exc))) from exc


def analyze_snapshot(data, include_recommendations=False, redactor=None):
    """Turn a collector snapshot into a list of AuditCheck objects.

    System-level checks run even when no Mihomo config is present. Returns
    a plain list; agents decide how to present it.
    """
    if not isinstance(data, dict):
        raise TypeError("snapshot must be a dictionary")

    checks = []

    def add(check_id, title, category, status, severity, explanation, recommendation=""):
        checks.append(AuditCheck(
            id=check_id,
            title=title,
            category=category,
            status=status,
            severity=severity,
            confidence="probable" if status == "warning" else "confirmed" if status in ("pass", "fail") else "unknown",
            explanation=explanation,
            recommendation=recommendation if include_recommendations else "",
        ))

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

    # System-level network and locale checks (run even when no Mihomo config is present)
    system = data.get("System")
    if isinstance(system, dict):
        # Service mode: process, service, and mixed-port listener
        proc_running = system.get("MihomoProcessRunning")
        service_active = system.get("ServiceModeActive")
        mixed_listening = system.get("MixedPortListening")
        if proc_running is not None:
            parts = []
            if proc_running:
                parts.append("process running")
            if service_active:
                parts.append("service mode active")
            if mixed_listening:
                parts.append("mixed-port listener present")
            if proc_running and service_active and mixed_listening:
                status, sev, expl = "pass", "info", "Observed " + ", ".join(parts) + "."
            elif not parts:
                status, sev, expl = "unknown", "info", "No Mihomo process, service, or mixed-port listener observed; confirm whether a proxy client is expected."
            else:
                status, sev, expl = "warning", "low", "Partial service state: " + ", ".join(parts) + "."
            add("network.service", "Mihomo service mode", "network", status, sev, expl,
                "Confirm the intended service mode and mixed-port listener in the active proxy client.")

        # Teredo state
        teredo = system.get("Teredo")
        if isinstance(teredo, dict):
            available = teredo.get("Available")
            teredo_disabled = teredo.get("Disabled") is True
            status = "pass" if teredo_disabled else "warning" if available is True else "unknown"
            add("network.teredo", "Teredo state", "network",
                status,
                "low" if status == "warning" else "info",
                "Teredo is disabled." if teredo_disabled
                else f"Teredo is available ({teredo.get('Type', 'unknown')}) and not disabled; confirm it cannot expose a physical-uplink route."
                if available is True else "Teredo state could not be read.",
                "Do not disable the Mihomo/tunnel adapter; address Teredo only if it demonstrably bypasses the proxy.")

        # Physical adapter IPv6 bindings
        bindings = system.get("ActiveAdapterIPv6Bindings")
        if isinstance(bindings, list):
            physical_enabled = [b for b in bindings
                                if isinstance(b, dict) and b.get("Classification") == "Physical" and b.get("Enabled")]
            status = "unknown" if not bindings else "pass" if not physical_enabled else "warning"
            add("network.ipv6_binding", "Physical adapter IPv6 binding", "network",
                status,
                "low" if status == "warning" else "info",
                "IPv6 adapter bindings could not be read." if not bindings
                else "No physical adapter exposes enabled IPv6." if not physical_enabled
                else f"{len(physical_enabled)} physical adapter(s) have IPv6 enabled; confirm no physical-uplink bypass.",
                "Adjust IPv6 only when it demonstrably bypasses the proxy; do not disable the tunnel adapter.")

        # Local DNS servers: flag physical-ISP IPv4 resolvers that could bypass the tunnel
        dns_servers = system.get("LocalDnsServers")
        if isinstance(dns_servers, list) and dns_servers:
            physical_ipv4 = 0
            unclassified_ipv4 = 0
            unknown_ipv4 = 0
            for entry in dns_servers:
                if not isinstance(entry, dict):
                    continue
                iface = str(entry.get("Interface", ""))
                classification = entry.get("Classification")
                if classification in ("TunnelOrVpn", "VirtualOrOther") or any(
                    token in iface.lower()
                    for token in ("sstap", "tun", "tap", "vpn", "openvpn", "virtual", "loopback", "hyper-v")
                ):
                    continue
                family = entry.get("Family")
                server_classes = entry.get("ServerClasses")
                if isinstance(server_classes, list):
                    nonlocal_count = sum(str(item).lower() == "other" for item in server_classes)
                    unknown_count = sum(str(item).lower() == "unknown" for item in server_classes)
                else:
                    servers = entry.get("Servers") or []
                    nonlocal_count = sum(
                        bool(server) and not _is_local_or_fake_dns(server)
                        for server in servers
                    ) if isinstance(servers, list) else 0
                    unknown_count = 0
                if family in (2, "2", "ipv4", "IPv4"):
                    unknown_ipv4 += unknown_count
                if family in (2, "2", "ipv4", "IPv4") and nonlocal_count:
                    if classification == "Physical" or classification is None and iface:
                        physical_ipv4 += nonlocal_count
                    else:
                        unclassified_ipv4 += nonlocal_count
            if physical_ipv4:
                protected = mihomo_protects_dns(data)
                add("network.dns_physical_resolver", "Physical-ISP DNS resolver", "network",
                    "unknown" if protected else "warning", "info" if protected else "low",
                    ("Physical adapter DNS resolver(s) are configured, but fake-IP plus port-53 hijacking is enabled; static configuration cannot prove a leak."
                     if protected else f"{physical_ipv4} non-local DNS resolver class(es) are configured on physical adapter(s)."),
                    "With fake-IP and port-53 hijacking active these are usually inert, but confirm a live test shows no physical-ISP resolver.")
            elif unclassified_ipv4:
                add("network.dns_physical_resolver", "Physical-ISP DNS resolver", "network", "unknown", "info",
                    "DNS resolver configuration was observed on adapter(s) whose physical or tunnel classification is unavailable.",
                    "Use an approved controlled DNS test before concluding that a physical resolver is active.")
            elif unknown_ipv4:
                add("network.dns_physical_resolver", "Physical-ISP DNS resolver", "network", "unknown", "info",
                    "One or more DNS resolver addresses could not be classified.",
                    "Use an approved controlled DNS test before drawing a conclusion.")
            else:
                add("network.dns_physical_resolver", "Physical-ISP DNS resolver", "network",
                    "pass", "info",
                    "No physical-ISP IPv4 resolver observed; tunnel or loopback resolvers only.",
                    "")

        # Environment proxy variables (existence only — values are never revealed)
        env_proxies = system.get("ProxyEnvironmentVariables")
        if isinstance(env_proxies, list):
            present = sorted({p.get("Name") for p in env_proxies
                              if isinstance(p, dict) and p.get("Present")})
            if present:
                add("network.env_proxy", "Environment proxy variables", "network",
                    "unknown", "info",
                    f"Proxy environment variables present: {', '.join(present)}.",
                    "Explain whether each is intentional; values are never revealed.")
            else:
                add("network.env_proxy", "Environment proxy variables", "network",
                    "pass", "info",
                    "No proxy environment variables are set.",
                    "")

        system_proxy = system.get("SystemProxy")
        if isinstance(system_proxy, dict):
            enabled, loopback = system_proxy.get("Enabled"), system_proxy.get("PointsToLoopback")
            status = "pass" if enabled is True and loopback is True else "unknown"
            add("network.system_proxy", "System proxy setting", "network", status, "info",
                "System proxy is enabled and points to loopback." if status == "pass"
                else "System proxy settings are static configuration only; runtime routing was not verified.", "")

        other_client_count = system.get("OtherProxyClientCount")
        other_clients = system.get("OtherProxyClientsRunning")
        if isinstance(other_client_count, int) and not isinstance(other_client_count, bool):
            add("network.other_proxy_clients", "Other proxy clients", "network",
                "unknown" if other_client_count else "pass", "info",
                f"{other_client_count} other supported proxy client process(es) were observed; process state does not prove a leak."
                if other_client_count else "No other supported proxy clients observed.", "")
        elif isinstance(other_clients, list):
            running = [str(item.get("Name", "unknown")) for item in other_clients if isinstance(item, dict) and item.get("Running")]
            add("network.other_proxy_clients", "Other proxy clients", "network",
                "unknown" if running else "pass", "info",
                f"Other proxy client(s) observed: {', '.join(running)}; static process state does not prove a leak." if running
                else "No other supported proxy clients observed.", "")

        # Windows locale consistency
        culture = system.get("Culture")
        ui_culture = system.get("UICulture")
        sys_locale = system.get("SystemLocale")
        langs = system.get("UserLanguageList")
        primary_lang = langs[0] if isinstance(langs, list) and langs else None
        locale_set = {c for c in (culture, ui_culture, sys_locale) if c}
        mismatches = []
        if len(locale_set) > 1:
            mismatches.append("Culture/UICulture/SystemLocale differ")
        if primary_lang and culture and not primary_lang.lower().startswith(culture.split("-")[0].lower()):
            mismatches.append("primary user language differs from culture")
        if mismatches:
            add("system.locale", "Windows locale consistency", "system", "warning", "info", "; ".join(mismatches) + ".", "Only change values that reflect genuine long-term use.")
        elif locale_set:
            add("system.locale", "Windows locale consistency", "system", "pass", "info", f"Locale is consistent (culture {culture}).", "")
        else:
            add("system.locale", "Windows locale consistency", "system", "unknown", "info", "Locale information is incomplete.", "")

    browsers = data.get("Browsers")
    if isinstance(browsers, dict):
        for browser, audit in browsers.items():
            if not isinstance(audit, dict) or audit.get("Installed") is False:
                continue
            restricted = audit.get("RestrictiveWebRtcPolicyDetected")
            add(f"browser.webrtc.{str(browser).lower()}", f"{browser} WebRTC policy", "browser",
                "pass" if restricted is True else "unknown", "info",
                "A restrictive WebRTC policy is configured." if restricted is True
                else "WebRTC runtime behavior was not verified; browser settings alone do not prove a leak.", "")

    mihomo = data.get("Mihomo")
    if not isinstance(mihomo, dict) or not (mihomo.get("AppConfigPresent") or mihomo.get("RuntimeConfigPresent")):
        add("network.mihomo", "Mihomo configuration", "network", "unknown", "info", "No Mihomo runtime configuration was available for automatic interpretation.")
        return _redact_checks(checks, redactor or Redactor())

    expected = [
        ("Mode", "Rule", "network.mode", "Rule mode"),
        ("AllowLan", False, "network.allow_lan", "LAN access disabled"),
        ("TunEnabled", True, "network.tun", "TUN enabled"),
        ("StrictRoute", True, "network.strict_route", "Strict routing enabled"),
        ("DnsEnabled", True, "network.dns", "Mihomo DNS enabled"),
        ("DnsMode", "fake-ip", "network.dns_mode", "Fake-IP DNS mode"),
        ("DnsHijackAny53", True, "network.dns_hijack", "DNS port 53 hijacking"),
    ]
    for key, wanted, check_id, title in expected:
        value = mihomo.get(key)
        matches = str(value).lower() == str(wanted).lower() if value is not None else None
        status = "pass" if matches else "unknown" if matches is None else "warning"
        add(
            check_id,
            title,
            "network",
            status,
            "info" if status != "warning" else "low",
            f"Observed {key}={value!r}." if value is not None else f"{key} requires manual confirmation.",
            "Confirm the setting in the active proxy client before changing it.",
        )

    # DNS respect-rules: must be enabled so fake-IP resolution honors rule routing
    respect_rules = mihomo.get("DnsRespectRules")
    if respect_rules is not None:
        status = "pass" if respect_rules else "warning"
        add("network.dns_respect_rules", "DNS respect-rules", "network", status,
            "info" if status == "pass" else "low",
            f"Observed DnsRespectRules={respect_rules!r}.",
            "Enable respect-rules so DNS resolution follows rule routing instead of bypassing the proxy.")

    # DNS IPv6: report consistency with the IPv6 toggle, do not judge alone
    dns_ipv6 = mihomo.get("DnsIPv6")
    ipv6 = mihomo.get("IPv6")
    if dns_ipv6 is not None:
        consistent = (dns_ipv6 == ipv6) if ipv6 is not None else None
        status = "pass" if consistent else "unknown" if consistent is None else "warning"
        add("network.dns_ipv6", "DNS IPv6 consistency", "network", status,
            "info" if status != "warning" else "low",
            f"Observed DnsIPv6={dns_ipv6!r}, IPv6={ipv6!r}."
            if ipv6 is not None else f"Observed DnsIPv6={dns_ipv6!r}.",
            "Confirm whether IPv6 DNS resolution is intended given the IPv6 routing toggle.")

    # Encrypted DNS upstreams: presence of DoH/DoT upstreams
    upstreams = mihomo.get("EncryptedDnsUpstreams")
    if upstreams is not None:
        schemes = sorted({str(u.get("Scheme", "")).lower() for u in upstreams if isinstance(u, dict) and u.get("Scheme")})
        status = "pass" if schemes else "unknown"
        add("network.dns_encrypted", "Encrypted DNS upstreams", "network", status,
            "info",
            f"Encrypted upstream scheme(s) present: {', '.join(schemes)}." if schemes
            else "No encrypted DNS upstream was observed; static configuration alone cannot establish the active DNS path.",
            "Verify the active DNS path before changing upstreams.")

    # TUN stack: informational, note non-gvisor stacks
    tun_stack = mihomo.get("TunStack")
    if tun_stack is not None:
        recommended = str(tun_stack).lower() == "gvisor"
        add("network.tun_stack", "TUN stack", "network",
            "pass" if recommended else "unknown",
            "info",
            f"Observed TunStack={tun_stack!r}; the stack choice alone does not establish a routing leak.",
            "Keep the stack already proven on this machine unless a controlled test shows a problem.")

    # Policy group: no automatic selectors in the selection chain
    policy = mihomo.get("PolicyGroups")
    if isinstance(policy, dict):
        runtime_groups = policy.get("RuntimeGroups")
        assessment = policy.get("SelectionAssessment")
        if isinstance(runtime_groups, list) and runtime_groups:
            automatic_types = []
            unresolved = False
            for g in runtime_groups:
                if not isinstance(g, dict):
                    continue
                if g.get("Resolved") is False:
                    unresolved = True
                selection_types = g.get("SelectionTypes")
                if not isinstance(selection_types, list):
                    selection_types = [
                        link.get("Type") for link in (g.get("SelectionChain") or [])
                        if isinstance(link, dict)
                    ]
                for selection_type in selection_types:
                    normalized = str(selection_type or "").lower().replace("_", "-")
                    if normalized in ("url-test", "urltest", "fallback", "load-balance", "loadbalance", "smart"):
                        automatic_types.append(str(selection_type))
                if g.get("UsesAutomaticSelection") and not automatic_types:
                    automatic_types.append("automatic")
            fixed = assessment == "FixedSelection" and not unresolved
            status = "pass" if fixed and not automatic_types else "warning" if automatic_types else "unknown"
            explanation = f"Policy selection is fixed ({assessment!r}) with no automatic selectors."
            if automatic_types:
                explanation = f"Automatic selector type(s) present: {', '.join(dict.fromkeys(automatic_types))}."
            elif not fixed:
                explanation = "Policy selection could not be resolved from the local controller."
            add("network.policy_group", "Policy group selection", "network", status,
                "low" if status == "warning" else "info",
                explanation,
                "Pin the sensitive service group to a fixed manual selection; automatic selectors can change the exit unpredictably.")
        else:
            add("network.policy_group", "Policy group selection", "network", "unknown", "info",
                "Policy group runtime selection is unavailable; verify the selected group in the Clash Verge UI.")

    return _redact_checks(checks, redactor or Redactor())


def summarize(checks):
    """Count checks by severity. Returns a dict with the standard keys."""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for check in checks:
        summary[check.severity] = summary.get(check.severity, 0) + 1
    return summary


def _is_local_or_fake_dns(server):
    import ipaddress
    try:
        address = ipaddress.ip_address(str(server))
        return address.is_loopback or address in ipaddress.ip_network("198.18.0.0/15")
    except ValueError:
        return False


def mihomo_protects_dns(data):
    mihomo = data.get("Mihomo")
    return (isinstance(mihomo, dict) and mihomo.get("DnsEnabled") is True
            and str(mihomo.get("DnsMode", "")).lower() == "fake-ip"
            and mihomo.get("DnsHijackAny53") is True)


def _redact_checks(checks, redactor):
    return [replace(check,
        title=redactor.scan_and_redact(check.title),
        explanation=redactor.scan_and_redact(check.explanation),
        recommendation=redactor.scan_and_redact(check.recommendation),
        evidence=[replace(item, description=redactor.scan_and_redact(item.description), data=redactor.scan_and_redact(item.data)) for item in check.evidence],
    ) for check in checks]


def run_full_audit(probe_timeout=5, include_recommendations=False, online=False):
    """One-call audit: run the collector, analyze locally, and optionally probe online.

    Returns a dict with ``checks`` (list[AuditCheck], local analysis first,
    then probe results), ``summary`` (severity counts), and ``snapshot``
    (redacted collector JSON for the agent's report context).

    Online probes are disabled by default; pass ``online=True`` to contact
    public endpoints.
    """
    from .probes.base import run_probes

    if online and (not isinstance(probe_timeout, (int, float)) or not 0 < probe_timeout <= 30):
        raise ValueError("Online probe timeout must be between 0 and 30 seconds.")

    snapshot = run_legacy_collector()
    redactor = Redactor()
    checks = analyze_snapshot(snapshot, include_recommendations=include_recommendations, redactor=redactor)
    try:
        probe_results = run_probes(None, timeout=probe_timeout, online=online)
        checks.extend(_redact_checks(probe_results, redactor))
    except Exception as exc:  # probes are best-effort; never fail the audit
        checks.extend(_redact_checks([AuditCheck(
            id="network.egress.probe_error",
            title="Online probe failure",
            category="network",
            status="unknown",
            severity="info",
            confidence="unknown",
            explanation=f"Online probes could not run: {exc}",
        )], redactor))
    return {
        "checks": checks,
        "summary": summarize(checks),
        "snapshot": redactor.scan_and_redact(snapshot),
    }
