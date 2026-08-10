from .common import evidence, is_local_or_fake_dns, mihomo_protects_dns


def collect_system_checks(data, builder):
    add = builder.add
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
        env_proxies = system.get("ProxyEnvironmentVariables")
        if isinstance(env_proxies, list):
            present = sorted({
                p.get("Name") for p in env_proxies
                if isinstance(p, dict) and p.get("Present")
            })
            if present:
                add(
                    "network.env_proxy",
                    "Environment proxy variables",
                    "network",
                    "unknown",
                    "info",
                    (
                        f"Proxy environment variables present: {', '.join(present)}. "
                        "Values are not shown; confirm each is intentional. "
                        "System proxy loopback is assessed separately (network.system_proxy)."
                    ),
                    "Explain whether each is intentional; values are never revealed.",
                    evidence=[evidence("env", "proxy env var names", {"names": list(present)})],
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

        system_proxy = system.get("SystemProxy")
        if isinstance(system_proxy, dict):
            enabled, loopback = system_proxy.get("Enabled"), system_proxy.get("PointsToLoopback")
            status = "pass" if enabled is True and loopback is True else "unknown"
            add(
                "network.system_proxy",
                "System proxy setting",
                "network",
                status,
                "info",
                "System proxy is enabled and points to loopback." if status == "pass"
                else "System proxy settings are static configuration only; runtime routing was not verified.",
                "",
                evidence=[evidence(
                    "system_proxy",
                    "system proxy flags",
                    {"enabled": enabled, "points_to_loopback": loopback},
                )],
            )

        other_client_count = system.get("OtherProxyClientCount")
        other_clients = system.get("OtherProxyClientsRunning")
        if isinstance(other_client_count, int) and not isinstance(other_client_count, bool):
            add(
                "network.other_proxy_clients",
                "Other proxy clients",
                "network",
                "unknown" if other_client_count else "pass",
                "info",
                f"{other_client_count} other supported proxy client process(es) were observed; process state does not prove a leak."
                if other_client_count else "No other supported proxy clients observed.",
                "",
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
                "",
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
        if mismatches:
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
