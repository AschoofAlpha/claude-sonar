from .common import evidence, is_local_or_fake_dns, mihomo_protects_dns


def normalize_intended_mode(intended_mode):
    """Normalize intended routing mode aliases.

    Returns None | \"system_proxy\" | \"full_tunnel\".
    Accepts: system_proxy, system-proxy, full_tunnel, full-tunnel, tun.
    """
    if intended_mode is None:
        return None
    text = str(intended_mode).strip().lower().replace("-", "_")
    if not text:
        return None
    if text in ("system_proxy", "systemproxy", "proxy", "sysproxy"):
        return "system_proxy"
    if text in ("full_tunnel", "fulltunnel", "tun", "tunnel", "tun_mode"):
        return "full_tunnel"
    return None


def merge_geo_with_egress(checks):
    """Best-effort: if online reputation evidence has a country, enrich geo_stack.

    Offline geo_stack stays advisory; never recommends following proxy/node country.
    Mutates matching check explanations in place when possible; returns checks.
    """
    if not checks:
        return checks

    country = None
    for check in checks:
        check_id = getattr(check, "id", None) or (check.get("id") if isinstance(check, dict) else None)
        if check_id not in (
            "network.ip_reputation",
            "network.egress.reputation",
            "network.egress.ip_reputation",
        ):
            continue
        evidence_list = getattr(check, "evidence", None)
        if evidence_list is None and isinstance(check, dict):
            evidence_list = check.get("evidence") or []
        for item in evidence_list or []:
            data = getattr(item, "data", None)
            if data is None and isinstance(item, dict):
                data = item.get("data")
            if not isinstance(data, dict):
                continue
            for key in ("country_code", "country", "Country", "CountryCode"):
                raw = data.get(key)
                if raw is None:
                    continue
                text = str(raw).strip().upper()
                if len(text) == 2 and text.isalpha():
                    country = text
                    break
            if country:
                break
        if country:
            break

    if not country:
        return checks

    for check in checks:
        check_id = getattr(check, "id", None) or (check.get("id") if isinstance(check, dict) else None)
        if check_id != "consistency.geo_stack":
            continue
        note = (
            f" Online reputation observed country code {country} "
            f"(informational only — do not auto-follow proxy/node country)."
        )
        if hasattr(check, "explanation"):
            expl = check.explanation or ""
            if country not in expl and "Online reputation" not in expl:
                try:
                    check.explanation = expl.rstrip() + note
                except Exception:
                    pass
            # Prefer mutating evidence when dataclass allows
            try:
                for item in check.evidence or []:
                    data = getattr(item, "data", None)
                    if isinstance(data, dict) and "egress_country_code" not in data:
                        data = dict(data)
                        data["egress_country_code"] = country
                        item.data = data
                        break
            except Exception:
                pass
        elif isinstance(check, dict):
            expl = str(check.get("explanation") or "")
            if country not in expl and "Online reputation" not in expl:
                check["explanation"] = expl.rstrip() + note
        break

    return checks


def collect_system_checks(data, builder, intended_mode=None):
    add = builder.add
    mode = normalize_intended_mode(intended_mode)
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
                status, sev, expl = (
                    "unknown",
                    "info",
                    "No Mihomo process, service, or mixed-port listener observed; "
                    "confirm whether a proxy client is expected.",
                )
            else:
                status, sev, expl = "warning", "low", "Partial service state: " + ", ".join(parts) + "."
            add(
                "network.service",
                "Mihomo service mode",
                "network",
                status,
                sev,
                expl,
                "Confirm the intended service mode and mixed-port listener in the active proxy client.",
                evidence=[evidence(
                    "system_service",
                    "service state",
                    {
                        "process_running": proc_running,
                        "service_mode_active": service_active,
                        "mixed_port_listening": mixed_listening,
                    },
                )],
            )

        # Teredo state
        teredo = system.get("Teredo")
        if isinstance(teredo, dict):
            available = teredo.get("Available")
            teredo_disabled = teredo.get("Disabled") is True
            status = "pass" if teredo_disabled else "warning" if available is True else "unknown"
            add(
                "network.teredo",
                "Teredo state",
                "network",
                status,
                "low" if status == "warning" else "info",
                "Teredo is disabled." if teredo_disabled
                else f"Teredo is available ({teredo.get('Type', 'unknown')}) and not disabled; confirm it cannot expose a physical-uplink route."
                if available is True else "Teredo state could not be read.",
                "Do not disable the Mihomo/tunnel adapter; address Teredo only if it demonstrably bypasses the proxy.",
            )

        # Physical adapter IPv6 bindings
        bindings = system.get("ActiveAdapterIPv6Bindings")
        if isinstance(bindings, list):
            physical_enabled = [
                b for b in bindings
                if isinstance(b, dict) and b.get("Classification") == "Physical" and b.get("Enabled")
            ]
            status = "unknown" if not bindings else "pass" if not physical_enabled else "warning"
            add(
                "network.ipv6_binding",
                "Physical adapter IPv6 binding",
                "network",
                status,
                "low" if status == "warning" else "info",
                "IPv6 adapter bindings could not be read." if not bindings
                else "No physical adapter exposes enabled IPv6." if not physical_enabled
                else f"{len(physical_enabled)} physical adapter(s) have IPv6 enabled; confirm no physical-uplink bypass.",
                "Adjust IPv6 only when it demonstrably bypasses the proxy; do not disable the tunnel adapter.",
            )

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
                        bool(server) and not is_local_or_fake_dns(server)
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
                add(
                    "network.dns_physical_resolver",
                    "Physical-ISP DNS resolver",
                    "network",
                    "unknown" if protected else "warning",
                    "info" if protected else "low",
                    (
                        "Physical adapter DNS resolver(s) are configured, but fake-IP plus port-53 "
                        "hijacking is enabled; static configuration cannot prove a leak."
                        if protected
                        else f"{physical_ipv4} non-local DNS resolver class(es) are configured on physical adapter(s)."
                    ),
                    "With fake-IP and port-53 hijacking active these are usually inert, but confirm a live test shows no physical-ISP resolver.",
                    evidence=[evidence("system_dns", "physical resolver count", {"physical_ipv4_classes": physical_ipv4})],
                )
            elif unclassified_ipv4:
                add(
                    "network.dns_physical_resolver",
                    "Physical-ISP DNS resolver",
                    "network",
                    "unknown",
                    "info",
                    "DNS resolver configuration was observed on adapter(s) whose physical or tunnel classification is unavailable.",
                    "Use an approved controlled DNS test before concluding that a physical resolver is active.",
                )
            elif unknown_ipv4:
                add(
                    "network.dns_physical_resolver",
                    "Physical-ISP DNS resolver",
                    "network",
                    "unknown",
                    "info",
                    "One or more DNS resolver addresses could not be classified.",
                    "Use an approved controlled DNS test before drawing a conclusion.",
                )
            else:
                add(
                    "network.dns_physical_resolver",
                    "Physical-ISP DNS resolver",
                    "network",
                    "pass",
                    "info",
                    "No physical-ISP IPv4 resolver observed; tunnel or loopback resolvers only.",
                    "",
                )

        # Environment proxy variables (existence only — values are never revealed)
        system_proxy = system.get("SystemProxy") if isinstance(system.get("SystemProxy"), dict) else {}
        sys_proxy_enabled = system_proxy.get("Enabled")
        sys_proxy_loopback = system_proxy.get("PointsToLoopback")
        system_loopback_ok = sys_proxy_enabled is True and sys_proxy_loopback is True

        env_proxies = system.get("ProxyEnvironmentVariables")
        env_present_names = []
        if isinstance(env_proxies, list):
            env_present_names = sorted({
                p.get("Name") for p in env_proxies
                if isinstance(p, dict) and p.get("Present") and p.get("Name")
            })
            if env_present_names:
                if system_loopback_ok:
                    # Env vars alongside an intentional loopback system proxy are common
                    # (CLI tools); treat as pass with an advisory note — never print values.
                    add(
                        "network.env_proxy",
                        "Environment proxy variables",
                        "network",
                        "pass",
                        "info",
                        (
                            f"Proxy environment variables present: {', '.join(env_present_names)}. "
                            "Values are not shown. They exist alongside a loopback system proxy "
                            "(network.system_proxy); confirm each is intentional."
                        ),
                        "Consider confirming each env proxy name is intentional; values are never revealed.",
                        evidence=[evidence(
                            "env",
                            "proxy env var names",
                            {"names": list(env_present_names), "alongside_loopback_system_proxy": True},
                        )],
                    )
                else:
                    add(
                        "network.env_proxy",
                        "Environment proxy variables",
                        "network",
                        "unknown",
                        "info",
                        (
                            f"Proxy environment variables present: {', '.join(env_present_names)}. "
                            "Values are not shown; confirm each is intentional. "
                            "System proxy loopback is assessed separately (network.system_proxy)."
                        ),
                        "Consider confirming whether each is intentional; values are never revealed.",
                        evidence=[evidence("env", "proxy env var names", {"names": list(env_present_names)})],
                    )
            else:
                add(
                    "network.env_proxy",
                    "Environment proxy variables",
                    "network",
                    "pass",
                    "info",
                    "No proxy environment variables are set.",
                    "",
                )

        if isinstance(system_proxy, dict) and system_proxy:
            enabled, loopback = system_proxy.get("Enabled"), system_proxy.get("PointsToLoopback")
            status = "pass" if enabled is True and loopback is True else "unknown"
            port_mixed = system_proxy.get("PortLooksLikeMixed")
            expl = (
                "System proxy is enabled and points to loopback."
                if status == "pass"
                else "System proxy settings are static configuration only; runtime routing was not verified."
            )
            if status == "pass" and port_mixed is True:
                expl += " Port class looks like the configured mixed-port."
            elif status == "pass" and port_mixed is False:
                expl += " Port class does not match the configured mixed-port (confirm intentional)."
            # Intended mode note for system_proxy path
            if mode == "system_proxy" and status == "pass":
                expl += " Matches intended mode system_proxy."
            elif mode == "full_tunnel" and status == "pass":
                expl += " System proxy loopback is fine alongside full_tunnel when TUN owns the default route."
            add(
                "network.system_proxy",
                "System proxy setting",
                "network",
                status,
                "info",
                expl,
                "",
                evidence=[evidence(
                    "system_proxy",
                    "system proxy flags",
                    {
                        "enabled": enabled,
                        "points_to_loopback": loopback,
                        "port_looks_like_mixed": port_mixed,
                        "intended_mode": mode,
                    },
                )],
            )

        winhttp = system.get("WinHttpProxy") if isinstance(system.get("WinHttpProxy"), dict) else {}
        pac = system.get("ProxyAutoConfig") if isinstance(system.get("ProxyAutoConfig"), dict) else {}

        # PAC/WPAD presence (offline flags only) — always surface when System is present
        auto_detect = pac.get("AutoDetect") if pac else None
        pac_url_present = pac.get("AutoConfigURLPresent") if pac else None
        if auto_detect is True or pac_url_present is True:
            bits = []
            if auto_detect is True:
                bits.append("WPAD AutoDetect is enabled")
            if pac_url_present is True:
                bits.append("an AutoConfigURL (PAC) is present")
            add(
                "network.proxy_autoconfig",
                "Proxy auto-configuration (PAC/WPAD)",
                "network",
                "warning",
                "info",
                (
                    " and ".join(bits) + ". PAC/WPAD may route some apps differently "
                    "from the explicit system proxy; confirm this is intentional."
                ),
                "Consider confirming whether PAC/WPAD is intentional; do not assume it matches system proxy.",
                evidence=[evidence(
                    "proxy_autoconfig",
                    "PAC/WPAD flags",
                    {"auto_detect": auto_detect, "auto_config_url_present": pac_url_present},
                )],
            )
        elif pac_url_present is False and auto_detect is not True:
            # No PAC URL. Missing AutoDetect registry value is common and treated as off.
            ad_txt = (
                "AutoDetect is off"
                if auto_detect is False
                else "AutoDetect registry value not present (typically off)"
            )
            add(
                "network.proxy_autoconfig",
                "Proxy auto-configuration (PAC/WPAD)",
                "network",
                "pass",
                "info",
                f"No PAC URL; {ad_txt}.",
                "",
                evidence=[evidence(
                    "proxy_autoconfig",
                    "PAC/WPAD flags",
                    {"auto_detect": auto_detect, "auto_config_url_present": pac_url_present},
                )],
            )
        elif "ProxyAutoConfig" not in system or (auto_detect is None and pac_url_present is None and not pac):
            add(
                "network.proxy_autoconfig",
                "Proxy auto-configuration (PAC/WPAD)",
                "network",
                "unknown",
                "info",
                "Proxy auto-configuration flags were not collected.",
                "Consider re-running the Windows collector if PAC/WPAD posture matters.",
            )
        else:
            # Partial: e.g. PAC presence unknown while AutoDetect is explicit
            add(
                "network.proxy_autoconfig",
                "Proxy auto-configuration (PAC/WPAD)",
                "network",
                "unknown",
                "info",
                "Proxy auto-configuration flags are incomplete.",
                "Consider confirming AutoDetect and PAC URL presence in Internet Settings.",
                evidence=[evidence(
                    "proxy_autoconfig",
                    "PAC/WPAD flags",
                    {"auto_detect": auto_detect, "auto_config_url_present": pac_url_present},
                )],
            )

        # Multi-layer proxy consistency: SystemProxy + WinHTTP + env presence
        has_layer_keys = (
            bool(system_proxy)
            or bool(winhttp)
            or bool(env_present_names)
            or bool(pac)
            or "SystemProxy" in system
            or "WinHttpProxy" in system
            or "ProxyAutoConfig" in system
            or isinstance(system.get("ProxyEnvironmentVariables"), list)
        )
        if has_layer_keys:
            wh_enabled = winhttp.get("Enabled") if winhttp else None
            wh_loopback = winhttp.get("PointsToLoopback") if winhttp else None
            wh_has_list = winhttp.get("HasProxyList") if winhttp else None
            auto_detect = pac.get("AutoDetect") if pac else None
            pac_url_present = pac.get("AutoConfigURLPresent") if pac else None

            layers_evidence = evidence(
                "proxy_layers",
                "proxy layer flags",
                {
                    "system_enabled": sys_proxy_enabled,
                    "system_loopback": sys_proxy_loopback,
                    "winhttp_enabled": wh_enabled,
                    "winhttp_loopback": wh_loopback,
                    "winhttp_has_proxy_list": wh_has_list,
                    "env_proxy_present": bool(env_present_names),
                    "auto_detect": auto_detect,
                    "auto_config_url_present": pac_url_present,
                    "intended_mode": mode,
                },
            )

            incomplete = (
                sys_proxy_enabled is None
                and wh_enabled is None
                and not env_present_names
                and auto_detect is None
                and pac_url_present is None
            )
            # WinHTTP "not conflicting": direct (disabled / no list) OR also loopback
            winhttp_direct = (
                wh_enabled is False
                or (wh_has_list is False and wh_enabled is not True)
            )
            winhttp_loopback_ok = wh_enabled is True and wh_loopback is True
            winhttp_ok = winhttp_direct or winhttp_loopback_ok or wh_enabled is None
            winhttp_conflict = (
                wh_enabled is True
                and wh_loopback is False
                and system_loopback_ok
            )
            # WinHTTP enabled non-loopback without system loopback is also a soft conflict
            winhttp_standalone_non_loopback = (
                wh_enabled is True
                and wh_loopback is False
                and not system_loopback_ok
            )
            pac_with_system = system_loopback_ok and (
                auto_detect is True or pac_url_present is True
            )

            if incomplete:
                add(
                    "network.proxy_layers",
                    "Proxy layer consistency",
                    "network",
                    "unknown",
                    "info",
                    "Proxy layer flags are incomplete; cannot compare system, WinHTTP, and env.",
                    "Consider re-collecting System proxy fields if multi-layer consistency matters.",
                    evidence=[layers_evidence],
                )
            elif winhttp_conflict:
                add(
                    "network.proxy_layers",
                    "Proxy layer consistency",
                    "network",
                    "warning",
                    "info",
                    (
                        "System proxy points to loopback but WinHTTP proxy is enabled and "
                        "does not point to loopback; some apps may bypass the local client."
                    ),
                    "Consider aligning WinHTTP with the loopback system proxy, or confirm WinHTTP direct access is intended.",
                    evidence=[layers_evidence],
                )
            elif winhttp_standalone_non_loopback and mode == "system_proxy":
                add(
                    "network.proxy_layers",
                    "Proxy layer consistency",
                    "network",
                    "warning",
                    "info",
                    (
                        "WinHTTP proxy is enabled and does not point to loopback while intended "
                        "mode is system_proxy; WinHTTP-using apps may bypass the local client."
                    ),
                    "Consider setting WinHTTP to direct or loopback to match system_proxy intent.",
                    evidence=[layers_evidence],
                )
            elif pac_with_system:
                add(
                    "network.proxy_layers",
                    "Proxy layer consistency",
                    "network",
                    "warning",
                    "info",
                    (
                        "System proxy is loopback-enabled while PAC/WPAD auto-config is active; "
                        "PAC/WPAD may bypass expected routing for some clients."
                    ),
                    "Consider confirming whether PAC/WPAD should stay enabled alongside the system proxy.",
                    evidence=[layers_evidence],
                )
            elif system_loopback_ok and winhttp_ok:
                bits = ["system proxy loopback"]
                if winhttp_loopback_ok:
                    bits.append("WinHTTP loopback")
                elif winhttp_direct:
                    bits.append("WinHTTP direct/no list")
                elif wh_enabled is None:
                    bits.append("WinHTTP not reported")
                if env_present_names:
                    bits.append("env proxy names present")
                add(
                    "network.proxy_layers",
                    "Proxy layer consistency",
                    "network",
                    "pass",
                    "info",
                    "Proxy layers look consistent: " + "; ".join(bits) + ".",
                    "",
                    evidence=[layers_evidence],
                )
            elif sys_proxy_enabled is True and sys_proxy_loopback is False:
                add(
                    "network.proxy_layers",
                    "Proxy layer consistency",
                    "network",
                    "warning",
                    "info",
                    "System proxy is enabled but does not point to loopback; confirm the target is intentional.",
                    "Consider confirming the system proxy target class (values are never shown).",
                    evidence=[layers_evidence],
                )
            else:
                add(
                    "network.proxy_layers",
                    "Proxy layer consistency",
                    "network",
                    "unknown",
                    "info",
                    (
                        "Proxy layer comparison is inconclusive from static flags alone "
                        "(system/WinHTTP/env presence)."
                    ),
                    "Consider confirming which proxy layer each app uses; static flags do not prove routing.",
                    evidence=[layers_evidence],
                )

        # Default route classes (physical vs tunnel) vs intended mode
        default_route = system.get("DefaultRoute")
        if isinstance(default_route, dict) and default_route:
            has_phys = default_route.get("HasPhysicalDefault")
            has_tun = default_route.get("HasTunnelDefault")
            phys_lower = default_route.get("PhysicalMetricLower")
            route_evidence = [evidence(
                "default_route",
                "default route classes",
                {
                    "has_physical_default": has_phys,
                    "has_tunnel_default": has_tun,
                    "physical_metric_lower": phys_lower,
                    "intended_mode": mode,
                },
            )]
            if mode == "full_tunnel":
                if has_tun is True and phys_lower is not True:
                    add(
                        "network.default_route",
                        "Default route vs intended mode",
                        "network",
                        "pass",
                        "info",
                        (
                            "Tunnel default route is present and not overridden by a lower-metric "
                            "physical default; consistent with intended full_tunnel mode."
                        ),
                        "",
                        evidence=route_evidence,
                    )
                elif has_tun is True and phys_lower is True:
                    add(
                        "network.default_route",
                        "Default route vs intended mode",
                        "network",
                        "warning",
                        "info",
                        (
                            "Tunnel default exists but a physical default has a lower metric; "
                            "full_tunnel mode may not own the preferred default route."
                        ),
                        "Consider confirming TUN/strict-route owns the default route when full_tunnel is intended.",
                        evidence=route_evidence,
                    )
                elif has_tun is False:
                    add(
                        "network.default_route",
                        "Default route vs intended mode",
                        "network",
                        "warning",
                        "info",
                        (
                            "No tunnel default route observed while intended mode is full_tunnel; "
                            "traffic may use the physical uplink."
                        ),
                        "Enable TUN / full-tunnel routing if that is the intended mode, then re-check default routes.",
                        evidence=route_evidence,
                    )
                else:
                    add(
                        "network.default_route",
                        "Default route vs intended mode",
                        "network",
                        "unknown",
                        "info",
                        "Default route flags are incomplete for full_tunnel assessment.",
                        "Consider re-running the Windows collector with route permissions.",
                        evidence=route_evidence,
                    )
            elif mode == "system_proxy":
                # Physical default is expected; tunnel default optional/not required
                if has_phys is True or has_phys is None:
                    bits = []
                    if has_phys is True:
                        bits.append("physical default present")
                    if has_tun is True:
                        bits.append("tunnel default also present (optional)")
                    elif has_tun is False:
                        bits.append("no tunnel default (expected for system_proxy)")
                    add(
                        "network.default_route",
                        "Default route vs intended mode",
                        "network",
                        "pass",
                        "info",
                        (
                            "Default route posture is acceptable for intended system_proxy mode"
                            + (": " + "; ".join(bits) + "." if bits else ".")
                        ),
                        "",
                        evidence=route_evidence,
                    )
                else:
                    add(
                        "network.default_route",
                        "Default route vs intended mode",
                        "network",
                        "unknown",
                        "info",
                        "No physical default route observed; unusual for system_proxy mode but not proof of a leak.",
                        "Confirm the active default route if apps cannot reach the network.",
                        evidence=route_evidence,
                    )
            else:
                # Soft/unknown when intended mode not declared
                if has_tun is True and phys_lower is True:
                    add(
                        "network.default_route",
                        "Default route vs intended mode",
                        "network",
                        "unknown",
                        "info",
                        (
                            "Both physical and tunnel defaults exist; physical metric is lower. "
                            "Declare intended_mode (system_proxy | full_tunnel) for a firmer assessment."
                        ),
                        "Optional: pass intended_mode=full_tunnel or system_proxy on analyze/run_full_audit.",
                        evidence=route_evidence,
                    )
                elif has_tun is True:
                    add(
                        "network.default_route",
                        "Default route vs intended mode",
                        "network",
                        "pass",
                        "info",
                        "Tunnel default route is present (intended mode not declared; soft pass).",
                        "",
                        evidence=route_evidence,
                    )
                elif has_phys is True:
                    add(
                        "network.default_route",
                        "Default route vs intended mode",
                        "network",
                        "unknown",
                        "info",
                        (
                            "Only a physical default route was observed. "
                            "This is normal for system-proxy mode; declare intended_mode for a firmer assessment."
                        ),
                        "Optional: pass intended_mode=system_proxy or full_tunnel on analyze/run_full_audit.",
                        evidence=route_evidence,
                    )
                else:
                    add(
                        "network.default_route",
                        "Default route vs intended mode",
                        "network",
                        "unknown",
                        "info",
                        "Default route classes could not be classified.",
                        "",
                        evidence=route_evidence,
                    )

        # Browser Secure DNS / DoH — advisory dual-path when Mihomo DNS is on
        browser_doh = system.get("BrowserSecureDns")
        if isinstance(browser_doh, dict) and browser_doh:
            modes = {}
            for name in ("Chrome", "Edge"):
                val = browser_doh.get(name)
                if val is not None:
                    modes[name] = str(val).lower().strip()
            if modes:
                mihomo = data.get("Mihomo") if isinstance(data.get("Mihomo"), dict) else {}
                mihomo_dns_on = mihomo.get("DnsEnabled") is True
                dual_path = [
                    f"{name}={mode}"
                    for name, mode in modes.items()
                    if mode in ("secure", "automatic")
                ]
                doh_evidence = [evidence(
                    "browser_secure_dns",
                    "browser DoH mode classes",
                    {"modes": modes, "mihomo_dns_enabled": mihomo_dns_on},
                )]
                if dual_path and mihomo_dns_on:
                    add(
                        "network.browser_secure_dns",
                        "Browser Secure DNS / DoH",
                        "network",
                        "warning",
                        "info",
                        (
                            "Browser Secure DNS is active ("
                            + ", ".join(dual_path)
                            + ") while Mihomo DNS is enabled; browsers may resolve outside the proxy DNS path "
                            "(dual-path advisory only)."
                        ),
                        "Consider setting browser Secure DNS to off when Mihomo owns DNS, if a single DNS path is desired.",
                        evidence=doh_evidence,
                    )
                elif dual_path:
                    add(
                        "network.browser_secure_dns",
                        "Browser Secure DNS / DoH",
                        "network",
                        "unknown",
                        "info",
                        (
                            "Browser Secure DNS is active ("
                            + ", ".join(dual_path)
                            + "); Mihomo DNS is not confirmed enabled. Dual-path risk is inconclusive."
                        ),
                        "Confirm whether browser DoH is intentional relative to the proxy DNS path.",
                        evidence=doh_evidence,
                    )
                elif all(m in ("off", "unknown") for m in modes.values()):
                    if any(m == "off" for m in modes.values()):
                        add(
                            "network.browser_secure_dns",
                            "Browser Secure DNS / DoH",
                            "network",
                            "pass",
                            "info",
                            "Browser Secure DNS is off or unknown; no dual-path Secure DNS signal.",
                            "",
                            evidence=doh_evidence,
                        )
                    else:
                        add(
                            "network.browser_secure_dns",
                            "Browser Secure DNS / DoH",
                            "network",
                            "unknown",
                            "info",
                            "Browser Secure DNS mode could not be read from policy (unknown).",
                            "",
                            evidence=doh_evidence,
                        )
                else:
                    add(
                        "network.browser_secure_dns",
                        "Browser Secure DNS / DoH",
                        "network",
                        "unknown",
                        "info",
                        "Browser Secure DNS modes: "
                        + ", ".join(f"{k}={v}" for k, v in modes.items())
                        + ".",
                        "",
                        evidence=doh_evidence,
                    )

        other_client_count = system.get("OtherProxyClientCount")
        other_clients = system.get("OtherProxyClientsRunning")
        if isinstance(other_client_count, int) and not isinstance(other_client_count, bool):
            running_names = []
            if isinstance(other_clients, list):
                running_names = [
                    str(item.get("Name", "unknown"))
                    for item in other_clients
                    if isinstance(item, dict) and item.get("Running")
                ]
            detail = (
                f"{other_client_count} other supported proxy client process(es) were observed"
                + (f" ({', '.join(running_names)})" if running_names else "")
                + "; process state does not prove a leak."
            )
            add(
                "network.other_proxy_clients",
                "Other proxy clients",
                "network",
                "unknown" if other_client_count else "pass",
                "info",
                detail if other_client_count else "No other supported proxy clients observed.",
                "Consider confirming only one intentional proxy client owns system routing."
                if other_client_count else "",
            )
        elif isinstance(other_clients, list):
            running = [
                str(item.get("Name", "unknown"))
                for item in other_clients
                if isinstance(item, dict) and item.get("Running")
            ]
            add(
                "network.other_proxy_clients",
                "Other proxy clients",
                "network",
                "unknown" if running else "pass",
                "info",
                f"Other proxy client(s) observed: {', '.join(running)}; static process state does not prove a leak."
                if running else "No other supported proxy clients observed.",
                "Consider confirming only one intentional proxy client owns system routing."
                if running else "",
            )

        # Windows locale consistency — bilingual setups stay warning (optional consistency only)
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
        locale_evidence = [evidence(
            "locale",
            "locale fields",
            {
                "culture": culture,
                "ui_culture": ui_culture,
                "system_locale": sys_locale,
                "primary_language": primary_lang,
            },
        )]
        locale_status = None
        if mismatches:
            locale_status = "warning"
            add(
                "system.locale",
                "Windows locale consistency",
                "system",
                "warning",
                "info",
                "; ".join(mismatches) + ".",
                "Optional consistency only: change values only when they reflect genuine long-term use.",
                evidence=locale_evidence,
            )
        elif locale_set:
            locale_status = "pass"
            add(
                "system.locale",
                "Windows locale consistency",
                "system",
                "pass",
                "info",
                f"Locale is consistent (culture {culture}).",
                "",
                evidence=locale_evidence,
            )
        else:
            locale_status = "unknown"
            add(
                "system.locale",
                "Windows locale consistency",
                "system",
                "unknown",
                "info",
                "Locale information is incomplete.",
                "",
            )

        # Timezone — informational; present => pass/info, missing => unknown
        timezone = system.get("TimeZone")
        if timezone:
            add(
                "system.timezone",
                "System timezone",
                "system",
                "pass",
                "info",
                f"TimeZone is {timezone}.",
                "Optional consistency only: keep timezone truthful for the user's real location.",
                evidence=[evidence("timezone", "system timezone", {"timezone": timezone})],
            )
        elif "TimeZone" in system:
            add(
                "system.timezone",
                "System timezone",
                "system",
                "unknown",
                "info",
                "TimeZone field is present but empty.",
                "Optional consistency only: set a truthful timezone if one is expected.",
            )
        # If TimeZone key is entirely absent, leave unknown only when System dict is otherwise used;
        # emit unknown so agents can still surface the signal when System was collected without TZ.
        else:
            add(
                "system.timezone",
                "System timezone",
                "system",
                "unknown",
                "info",
                "TimeZone information is missing.",
                "Optional consistency only: timezone was not reported by the collector.",
            )

        # Offline geo stack: TimeZone + Culture/UICulture only.
        # Never recommend matching timezone to a proxy/node country.
        geo_cultures = [c for c in (culture, ui_culture) if c]
        geo_evidence = [evidence(
            "geo_stack",
            "timezone and culture",
            {
                "timezone": timezone or None,
                "culture": culture,
                "ui_culture": ui_culture,
            },
        )]
        geo_recommendation = (
            "Keep timezone and language truthful for real use; do not auto-follow a proxy/node country. "
            "Optional alignment only — consider confirming values reflect genuine long-term location and language."
        )
        if timezone and geo_cultures:
            if locale_status == "warning":
                add(
                    "consistency.geo_stack",
                    "Geo stack (timezone + locale)",
                    "system",
                    "warning",
                    "info",
                    (
                        f"TimeZone is {timezone}; culture/UI culture present but locale fields "
                        "already differ (see system.locale). Offline only — not tied to exit IP."
                    ),
                    geo_recommendation,
                    evidence=geo_evidence,
                )
            else:
                add(
                    "consistency.geo_stack",
                    "Geo stack (timezone + locale)",
                    "system",
                    "pass",
                    "info",
                    (
                        f"TimeZone ({timezone}) and culture/UI culture are present "
                        f"({', '.join(geo_cultures)}). Offline informational only."
                    ),
                    geo_recommendation,
                    evidence=geo_evidence,
                )
        elif timezone or geo_cultures:
            add(
                "consistency.geo_stack",
                "Geo stack (timezone + locale)",
                "system",
                "unknown",
                "info",
                "Geo stack is partial (timezone and/or culture incomplete).",
                geo_recommendation,
                evidence=geo_evidence,
            )
        else:
            add(
                "consistency.geo_stack",
                "Geo stack (timezone + locale)",
                "system",
                "unknown",
                "info",
                "Geo stack fields (TimeZone, Culture/UICulture) were not available.",
                geo_recommendation,
                evidence=geo_evidence,
            )
