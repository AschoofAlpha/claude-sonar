from .common import evidence

# Schemes that count as encrypted DNS upstreams (DoH / DoT / DoQ / H3).
_ENCRYPTED_DNS_SCHEMES = frozenset({
    "https", "h3", "http3", "tls", "quic", "dot", "doh", "doq",
})


def _normalize_encrypted_upstreams(upstreams):
    """Normalize EncryptedDnsUpstreams dual shape: dict OR list of dicts.

    Collectors may emit a single object ``{'Scheme': 'https'}`` (PowerShell
    ConvertTo-Json scalar collapse) or a list of such objects.
    """
    if upstreams is None:
        return []
    if isinstance(upstreams, dict):
        items = [upstreams]
    elif isinstance(upstreams, list):
        items = [item for item in upstreams if isinstance(item, dict)]
    else:
        return []
    schemes = []
    seen = set()
    for item in items:
        raw = item.get("Scheme")
        if raw is None or raw == "":
            continue
        scheme = str(raw).lower().strip()
        if scheme and scheme not in seen:
            seen.add(scheme)
            schemes.append(scheme)
    schemes.sort()
    return schemes


def collect_mihomo_checks(data, builder, intended_mode=None):
    """Return True if analysis should stop early (no mihomo config)."""
    from .system import normalize_intended_mode

    add = builder.add
    mode = normalize_intended_mode(intended_mode)
    mihomo = data.get("Mihomo")
    if not isinstance(mihomo, dict) or not (mihomo.get("AppConfigPresent") or mihomo.get("RuntimeConfigPresent")):
        add(
            "network.mihomo",
            "Mihomo configuration",
            "network",
            "unknown",
            "info",
            "No Mihomo runtime configuration was available for automatic interpretation.",
        )
        return True

    expected = [
        ("Mode", "Rule", "network.mode", "Rule mode"),
        ("AllowLan", False, "network.allow_lan", "LAN access disabled"),
        # TunEnabled handled separately — off is not an automatic fail
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
            evidence=[evidence("mihomo_config", f"{key}", {"key": key, "value": value})] if value is not None else None,
        )

    # TUN vs intended_mode:
    # - system_proxy + TunEnabled False => pass (intentional)
    # - full_tunnel + TunEnabled False => warning (optional/must-ish with clear rec)
    # - full_tunnel + TunEnabled True => pass
    # - None => keep soft unknown when off
    tun_value = mihomo.get("TunEnabled")
    tun_evidence = (
        [evidence(
            "mihomo_config",
            "TunEnabled",
            {"key": "TunEnabled", "value": tun_value, "intended_mode": mode},
        )]
        if tun_value is not None
        else [evidence("mihomo_config", "TunEnabled", {"intended_mode": mode})]
    )
    if tun_value is None:
        add(
            "network.tun",
            "TUN enabled",
            "network",
            "unknown",
            "info",
            "TunEnabled requires manual confirmation."
            + (f" Intended mode is {mode}." if mode else ""),
            "Confirm the intended mode (TUN vs system-proxy) in the active proxy client.",
            evidence=tun_evidence,
        )
    else:
        tun_on = str(tun_value).lower() in ("true", "1", "yes")
        if tun_on:
            if mode == "system_proxy":
                add(
                    "network.tun",
                    "TUN enabled",
                    "network",
                    "unknown",
                    "info",
                    (
                        f"Observed TunEnabled={tun_value!r} while intended mode is system_proxy. "
                        "TUN-on with system-proxy intent may be redundant; confirm the intended routing mode."
                    ),
                    "If system_proxy is intended, TUN may be turned off; if full_tunnel is intended, keep TUN.",
                    evidence=tun_evidence,
                )
            else:
                add(
                    "network.tun",
                    "TUN enabled",
                    "network",
                    "pass",
                    "info",
                    f"Observed TunEnabled={tun_value!r}."
                    + (" Matches intended full_tunnel mode." if mode == "full_tunnel" else ""),
                    "Confirm the setting in the active proxy client before changing it.",
                    evidence=tun_evidence,
                )
        elif mode == "system_proxy":
            add(
                "network.tun",
                "TUN enabled",
                "network",
                "pass",
                "info",
                (
                    f"Observed TunEnabled={tun_value!r}. "
                    "Matches intended system_proxy mode (TUN off is intentional)."
                ),
                "",
                evidence=tun_evidence,
            )
        elif mode == "full_tunnel":
            add(
                "network.tun",
                "TUN enabled",
                "network",
                "warning",
                "info",
                (
                    f"Observed TunEnabled={tun_value!r} while intended mode is full_tunnel. "
                    "Full-tunnel routing expects TUN enabled."
                ),
                "Enable TUN (full-tunnel) in the active proxy client if full_tunnel is the intended mode.",
                evidence=tun_evidence,
            )
        else:
            add(
                "network.tun",
                "TUN enabled",
                "network",
                "unknown",
                "info",
                (
                    f"Observed TunEnabled={tun_value!r}. "
                    "System-proxy mode may be intentional; confirm the intended mode "
                    "rather than treating TUN-off as an automatic failure."
                ),
                "Only enable TUN if it matches the intended routing mode; system-proxy alone is not a leak.",
                evidence=tun_evidence,
            )

    # DNS respect-rules: must be enabled so fake-IP resolution honors rule routing
    respect_rules = mihomo.get("DnsRespectRules")
    if respect_rules is not None:
        status = "pass" if respect_rules else "warning"
        add(
            "network.dns_respect_rules",
            "DNS respect-rules",
            "network",
            status,
            "info" if status == "pass" else "low",
            f"Observed DnsRespectRules={respect_rules!r}.",
            "Enable respect-rules so DNS resolution follows rule routing instead of bypassing the proxy.",
            evidence=[evidence("mihomo_config", "DnsRespectRules", {"value": respect_rules})],
        )

    # DNS IPv6: report consistency with the IPv6 toggle, do not judge alone
    dns_ipv6 = mihomo.get("DnsIPv6")
    ipv6 = mihomo.get("IPv6")
    if dns_ipv6 is not None:
        consistent = (dns_ipv6 == ipv6) if ipv6 is not None else None
        status = "pass" if consistent else "unknown" if consistent is None else "warning"
        add(
            "network.dns_ipv6",
            "DNS IPv6 consistency",
            "network",
            status,
            "info" if status != "warning" else "low",
            f"Observed DnsIPv6={dns_ipv6!r}, IPv6={ipv6!r}."
            if ipv6 is not None else f"Observed DnsIPv6={dns_ipv6!r}.",
            "Confirm whether IPv6 DNS resolution is intended given the IPv6 routing toggle.",
        )

    # Encrypted DNS upstreams: dual-shape dict OR list; scheme present => pass
    upstreams = mihomo.get("EncryptedDnsUpstreams")
    if upstreams is not None:
        schemes = _normalize_encrypted_upstreams(upstreams)
        encrypted = [s for s in schemes if s in _ENCRYPTED_DNS_SCHEMES]
        # Any recognized encrypted scheme (or any non-empty scheme tag) => pass
        if encrypted:
            status = "pass"
            explanation = f"Encrypted upstream scheme(s) present: {', '.join(encrypted)}."
        elif schemes:
            # Unknown scheme labels still indicate configured upstream tags
            status = "pass"
            explanation = f"DNS upstream scheme(s) present: {', '.join(schemes)}."
        else:
            status = "unknown"
            explanation = (
                "No encrypted DNS upstream was observed; static configuration alone "
                "cannot establish the active DNS path."
            )
        add(
            "network.dns_encrypted",
            "Encrypted DNS upstreams",
            "network",
            status,
            "info",
            explanation,
            "Verify the active DNS path before changing upstreams.",
            evidence=[evidence("mihomo_dns", "EncryptedDnsUpstreams", {"schemes": schemes})],
        )

    # TUN stack: informational, note non-gvisor stacks
    tun_stack = mihomo.get("TunStack")
    if tun_stack is not None:
        recommended = str(tun_stack).lower() == "gvisor"
        add(
            "network.tun_stack",
            "TUN stack",
            "network",
            "pass" if recommended else "unknown",
            "info",
            f"Observed TunStack={tun_stack!r}; the stack choice alone does not establish a routing leak.",
            "Keep the stack already proven on this machine unless a controlled test shows a problem.",
        )

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
            add(
                "network.policy_group",
                "Policy group selection",
                "network",
                status,
                "low" if status == "warning" else "info",
                explanation,
                "Pin the sensitive service group to a fixed manual selection; automatic selectors can change the exit unpredictably.",
            )
        else:
            add(
                "network.policy_group",
                "Policy group selection",
                "network",
                "unknown",
                "info",
                "Policy group runtime selection is unavailable; verify the selected group in the Clash Verge UI.",
            )

    return False
