def collect_mihomo_checks(data, builder):
    """Return True if analysis should stop early (no mihomo config)."""
    add = builder.add
    mihomo = data.get("Mihomo")
    if not isinstance(mihomo, dict) or not (mihomo.get("AppConfigPresent") or mihomo.get("RuntimeConfigPresent")):
        add("network.mihomo", "Mihomo configuration", "network", "unknown", "info", "No Mihomo runtime configuration was available for automatic interpretation.")
        return True

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

    return False
