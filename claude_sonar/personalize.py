"""Detect active proxy client and build personalized *manual* guidance.

Never auto-changes DNS, routes, TUN, IPv6, system proxy, timezone, or wipes
the environment. Guidance is recommend-only and always requires explicit user
action in their own app / OS settings.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# Process basename (no .exe) -> display label
_PROCESS_LABELS: Dict[str, str] = {
    "clash verge": "Clash Verge",
    "clash-verge": "Clash Verge",
    "clash verge rev": "Clash Verge Rev",
    "clash-verge-rev": "Clash Verge Rev",
    "clashvergerev": "Clash Verge Rev",
    "clash-meta": "Clash Meta",
    "clash": "Clash",
    "clash for windows": "Clash for Windows",
    "cfw": "Clash for Windows",
    "mihomo": "Mihomo",
    "mihomo-windows-amd64": "Mihomo",
    "verge-mihomo": "Clash Verge (Mihomo)",
    "v2rayn": "v2rayN",
    "v2ray": "v2ray",
    "xray": "Xray",
    "sing-box": "sing-box",
    "hiddify": "Hiddify",
    "nekobox": "NekoBox",
    "nestbox": "NekoBox",
    "hysteria": "Hysteria",
    "hysteria2": "Hysteria2",
    "netch": "Netch",
    "ssr": "SSR",
    "shadowsocks": "Shadowsocks",
    "ss-local": "Shadowsocks",
    "trojan": "Trojan",
}


def _norm_name(name: str) -> str:
    return str(name or "").strip().lower().replace(".exe", "").replace("_", "-")


_CLI_AGENT_HINTS = (
    "claude", "codex", "opencode", "gemini-cli", "aider", "cursor",
)


def detect_cli_agent(snapshot: Optional[dict]) -> bool:
    """Best-effort: is a terminal/CLI coding agent in use on this machine?

    Looks at Claude Code config/env presence in the snapshot (ClaudeCode
    section) plus common CLI-agent process names. Absence is not proof the
    user never uses a CLI — the report treats it as advisory.
    """
    data = snapshot if isinstance(snapshot, dict) else {}
    claude = data.get("ClaudeCode")
    if isinstance(claude, dict):
        # Any meaningful Claude Code signal counts as "likely CLI use".
        keys = [
            "DisableTelemetryVars",
            "DisableErrorReportingVars",
            "DisableNonessentialTrafficVars",
            "SkipPromptHistoryVars",
            "LocalArtifacts",
        ]
        for k in keys:
            v = claude.get(k)
            if isinstance(v, list) and v:
                return True
            if v:
                return True
    system = data.get("System")
    if isinstance(system, dict):
        procs = system.get("PrimaryProxyProcesses") or []
        other = system.get("OtherProxyClientsRunning") or []
        for lst in (procs, other):
            if not isinstance(lst, list):
                continue
            for item in lst:
                name = str(item.get("Name", "") if isinstance(item, dict) else item).lower()
                if any(h in name for h in _CLI_AGENT_HINTS):
                    return True
    return False


def _label_for(name: str) -> str:
    key = _norm_name(name)
    if key in _PROCESS_LABELS:
        return _PROCESS_LABELS[key]
    # fuzzy
    for k, lab in _PROCESS_LABELS.items():
        if k in key or key in k:
            return lab
    return str(name or "unknown").strip() or "unknown"


def detect_active_proxy(snapshot: Optional[dict]) -> Dict[str, Any]:
    """Return a compact active-proxy profile from a collector snapshot."""
    data = snapshot if isinstance(snapshot, dict) else {}
    system = data.get("System") if isinstance(data.get("System"), dict) else {}
    mihomo = data.get("Mihomo") if isinstance(data.get("Mihomo"), dict) else {}

    running: List[str] = []
    labels: List[str] = []

    # Explicit collector field (preferred)
    primary_list = system.get("PrimaryProxyProcesses") or system.get("ProxyClientProcesses")
    if isinstance(primary_list, list):
        for item in primary_list:
            if isinstance(item, dict) and item.get("Running"):
                n = str(item.get("Name") or "")
                if n:
                    running.append(n)
                    labels.append(str(item.get("Label") or _label_for(n)))
            elif isinstance(item, str) and item.strip():
                running.append(item.strip())
                labels.append(_label_for(item))

    others = system.get("OtherProxyClientsRunning")
    if isinstance(others, list):
        for item in others:
            if isinstance(item, dict) and item.get("Running"):
                n = str(item.get("Name") or "")
                if n and n not in running:
                    running.append(n)
                    labels.append(_label_for(n))

    mihomo_running = system.get("MihomoProcessRunning") is True
    service = system.get("ServiceModeActive") is True
    mixed = system.get("MixedPortListening") is True
    has_mihomo_cfg = bool(mihomo.get("ConfigPath") or mihomo.get("Mode") is not None or mihomo)

    if mihomo_running or service or (has_mihomo_cfg and mixed):
        # Prefer a UI client label if one is already running
        ui = next(
            (
                lab
                for lab in labels
                if any(x in lab.lower() for x in ("verge", "clash for windows", "hiddify", "v2rayn"))
            ),
            None,
        )
        if ui:
            primary = ui
            if "mihomo" not in ui.lower() and "meta" not in ui.lower():
                engine = "Mihomo/Meta"
            else:
                engine = "Mihomo"
        else:
            primary = "Mihomo（服务/核心）" if (service or mihomo_running) else "Mihomo/Clash 配置"
            engine = "Mihomo"
        if primary not in labels:
            labels.insert(0, primary)
        confidence = "high" if (mihomo_running or service) else "medium"
    elif labels:
        primary = labels[0]
        engine = primary
        confidence = "medium"
    else:
        primary = "未识别到常见代理客户端"
        engine = "unknown"
        confidence = "low"

    # De-duplicate labels preserving order (several process entries can map to
    # the same client display name, e.g. verge / verge-mihomo / clash-verge).
    labels = list(dict.fromkeys(str(x) for x in labels))

    return {
        "primary": primary,
        "engine": engine,
        "running_names": running,
        "labels": labels,
        "mihomo_process": mihomo_running,
        "service_mode": service,
        "mixed_port_listening": mixed,
        "confidence": confidence,
    }


def _field(check: Any, key: str, default=None):
    if isinstance(check, dict):
        return check.get(key, default)
    return getattr(check, key, default)


def _status_map(checks: Sequence[Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for c in checks or []:
        cid = str(_field(c, "id", "") or "")
        if cid:
            out[cid] = c
    return out


def _client_tips(primary: str, lang: str) -> List[str]:
    p = primary.lower()
    zh = lang != "en"
    if any(x in p for x in ("verge", "clash", "mihomo", "meta")):
        if zh:
            return [
                "打开 **Clash Verge / Mihomo 客户端** → 设置/内核：确认系统代理或 TUN。",
                "系统代理：设置里打开「系统代理」，端口与 mixed-port 一致。",
                "TUN 全隧道：设置 → 开启 TUN（需管理员）；适合 `full_tunnel` 意图。",
                "DNS：推荐 fake-ip + 劫持 53 + 加密上游（DoH）；浏览器 Secure DNS 建议关闭以免双轨。",
                "节点：策略组用**手动固定**，避免自动测速乱跳。",
                "**叫法对照：** 虚拟网卡模式 = TUN 模式（Clash Verge/Mihomo/Clash 系均如此叫）；"
                "有的客户端叫「全局模式」（但不一定接管全部流量），以「TUN/虚拟网卡」字样为准。",
            ]
        return [
            "Open Clash Verge / Mihomo → enable System Proxy or TUN as intended.",
            "System proxy port should match mixed-port.",
            "TUN needs elevation; use for full_tunnel intent.",
            "Prefer fake-ip + port-53 hijack + DoH; turn off browser Secure DNS if dual-path.",
            "Keep policy groups on manual/fixed selection.",
            "Note: “virtual adapter” mode = TUN mode in Clash-family clients; “global mode” alone may not capture everything.",
        ]
    if "v2ray" in p or "xray" in p:
        if zh:
            return [
                "打开 **v2rayN / Xray** → 参数设置：系统代理 / 路由模式。",
                "需要全局时用「自动配置系统代理」或 TUN 类模式（以客户端为准）。",
                "DNS 与路由规则在核心配置中检查，避免直连绕过。",
                "**叫法对照：** 虚拟网卡/TUN 在 v2rayN 里常叫「TUN 模式」；Xray 需在核心配置开启 tun 块。",
            ]
        return [
            "Open v2rayN/Xray → system proxy / routing mode.",
            "Use system proxy or TUN-style mode when you want broader capture.",
            "v2rayN calls TUN “TUN 模式”; Xray enables it via the tun block in config.",
        ]
    if "sing-box" in p or "hiddify" in p or "neko" in p:
        if zh:
            return [
                f"打开 **{primary}** → 查看系统代理 / TUN / DNS 面板。",
                "按你的意图开启系统代理或 TUN；DNS 尽量走客户端接管。",
                "**叫法对照：** sing-box/Hiddify/NekoBox 的虚拟网卡 = TUN（sing-box 配置里是 tun 块；Hiddify 面板里叫 TUN）。",
            ]
        return [f"Open **{primary}** → system proxy / TUN / DNS panels. TUN = virtual adapter."]
    if zh:
        return [
            f"当前识别为：**{primary}**。请在该软件设置中调整系统代理、TUN、DNS。",
            "改网络相关项前先确认只运行一个主力客户端，避免多开抢代理。",
            "**叫法对照：** 虚拟网卡 = TUN（绝大多数客户端如此命名）；「全局模式」不一定覆盖全部流量。",
        ]
    return [
        f"Detected **{primary}**. Adjust system proxy / TUN / DNS in that app.",
        "Avoid multiple proxy clients fighting for the system proxy.",
        "“Virtual adapter” usually means TUN mode; “global mode” alone may not cover everything.",
    ]


def build_personal_guidance(
    snapshot: Optional[dict],
    checks: Sequence[Any],
    *,
    intended_mode: Optional[str] = None,
    intended_region: Optional[str] = None,
    lang: str = "zh",
    cli_agent: Optional[bool] = None,
) -> Dict[str, Any]:
    """Build personalized recommend-only guidance block + optional synthetic notes."""
    lang = "en" if str(lang).lower().startswith("en") else "zh"
    profile = detect_active_proxy(snapshot)
    by_id = _status_map(checks)
    mode = (intended_mode or "").strip().lower().replace("-", "_")
    tips = _client_tips(str(profile.get("primary") or ""), lang)

    # CLI-agent detection: explicit override wins, else best-effort snapshot sniff.
    if cli_agent is None:
        cli_agent = detect_cli_agent(snapshot)

    actions: List[Dict[str, str]] = []

    def add_action(kind: str, title: str, detail: str) -> None:
        actions.append({"kind": kind, "title": title, "detail": detail})

    # CLI coding agents (Claude Code / Codex / …) often ignore the OS system
    # proxy — recommend global + TUN/virtual-adapter capture, app-named.
    if cli_agent:
        add_action(
            "cli_tun",
            (
                "CLI 端 Claude/Codex 建议：开全局 + 虚拟网卡(TUN)"
                if lang == "zh"
                else "CLI Claude/Codex: enable global + virtual adapter (TUN)"
            ),
            (
                f"CLI 工具（Claude Code / Codex 等）很多不读 Windows 系统代理，只认环境变量或直连。"
                f"若要让 CLI 流量也走梯子：在 **{profile.get('primary')}** 里开 **全局 + 虚拟网卡(TUN)** 模式"
                f"（各客户端叫法：Clash Verge/Mihomo 叫 TUN 或虚拟网卡；v2rayN 叫 TUN 模式；"
                f"sing-box/Hiddify 叫 TUN；部分叫「全局模式」但不一定覆盖全部流量）。"
                f"也可给终端设 HTTPS_PROXY 指向 {profile.get('primary')} 的端口。"
                f"本工具不会自动改 TUN 或代理设置。"
                if lang == "zh"
                else f"CLI agents (Claude Code / Codex …) often bypass the OS system proxy. "
                f"To route them too: enable **global + virtual adapter (TUN)** in **{profile.get('primary')}** "
                f"(names vary: Clash Verge/Mihomo call it TUN/virtual adapter, v2rayN TUN 模式, "
                f"sing-box/Hiddify TUN; “global mode” alone may not cover everything), "
                f"or export HTTPS_PROXY for the terminal. This tool will not change TUN/proxy settings."
            ),
        )

    # TUN
    tun = by_id.get("network.tun")
    tun_st = str(_field(tun, "status", "") or "")
    if mode in ("full_tunnel", "tun", "fulltunnel") and tun_st in ("unknown", "warning", "fail"):
        add_action(
            "tun",
            "开启 TUN（全隧道）" if lang == "zh" else "Enable TUN (full tunnel)",
            (
                f"在 **{profile.get('primary')}** 中开启 TUN（通常需管理员）。"
                "本工具不会替你打开 TUN。"
                if lang == "zh"
                else f"Enable TUN in **{profile.get('primary')}** (often needs admin). "
                "This tool will not flip TUN for you."
            ),
        )
    elif mode in ("system_proxy", "systemproxy") and tun_st == "pass":
        if cli_agent:
            add_action(
                "tun",
                "系统代理模式下 TUN 可保持关闭；CLI 全覆盖才需要开 TUN"
                if lang == "zh"
                else "TUN may stay off in system_proxy mode; enable only for CLI-wide capture",
                (
                    f"当前 intent 为 system_proxy，TUN 关闭是合理的（GUI/浏览器走系统代理）。"
                    f"若你确实需要 **CLI 流量也全覆盖**，再在 **{profile.get('primary')}** 手动开 TUN（虚拟网卡），"
                    f"并把使用方式视为 full_tunnel。两条路都可行，按你的实际用法选。"
                    if lang == "zh"
                    else f"system_proxy intent means TUN off is fine (GUI/browsers use the OS proxy). "
                    f"If you truly need CLI-wide capture, enable TUN manually in **{profile.get('primary')}** "
                    f"and treat usage as full_tunnel. Either is valid — pick by how you actually use it."
                ),
            )
        else:
            add_action(
                "tun",
                "保持 TUN 关闭（系统代理模式）" if lang == "zh" else "Keep TUN off (system proxy mode)",
                (
                    "当前意图为系统代理，TUN 关闭是合理的；无需改。"
                    if lang == "zh"
                    else "TUN off matches system_proxy intent; no change needed."
                ),
            )

    # System proxy
    sp = by_id.get("network.system_proxy")
    if str(_field(sp, "status", "") or "") != "pass":
        add_action(
            "system_proxy",
            "打开系统代理并指向本机端口" if lang == "zh" else "Enable system proxy → loopback",
            (
                f"在 **{profile.get('primary')}** 打开系统代理，确保指向 127.0.0.1/mixed-port。"
                "也可在 Windows「代理」设置中核对。本工具不会自动改系统代理。"
                if lang == "zh"
                else f"Enable system proxy in **{profile.get('primary')}** to loopback/mixed-port. "
                "This tool will not change Windows proxy settings for you."
            ),
        )

    # DNS
    dns_issues = []
    for cid in (
        "network.dns",
        "network.dns_hijack",
        "network.dns_encrypted",
        "network.browser_secure_dns",
    ):
        c = by_id.get(cid)
        if c and str(_field(c, "status", "") or "") in ("warning", "fail"):
            dns_issues.append(cid)
    if dns_issues:
        add_action(
            "dns",
            "整理 DNS 路径" if lang == "zh" else "Align DNS path",
            (
                f"在 **{profile.get('primary')}** 检查 DNS/fake-ip/劫持；浏览器 Secure DNS 若开启可改为关闭以免双轨。"
                "本工具不会自动改 DNS。"
                if lang == "zh"
                else f"Review DNS/fake-ip/hijack in **{profile.get('primary')}**; "
                "consider turning off browser Secure DNS. This tool will not edit DNS for you."
            ),
        )

    # IPv6 / route
    for cid, title_zh, title_en in (
        ("network.ipv6_binding", "检查物理网卡 IPv6", "Review physical IPv6"),
        ("network.default_route", "检查默认路由", "Review default route"),
        ("network.teredo", "关闭 Teredo（若仍开启）", "Disable Teredo if still on"),
    ):
        c = by_id.get(cid)
        if c and str(_field(c, "status", "") or "") in ("warning", "fail"):
            add_action(
                "route",
                title_zh if lang == "zh" else title_en,
                (
                    "可在网卡/系统设置或代理客户端中调整；请先确认不会误关隧道适配器。"
                    "本工具不会自动改路由或 IPv6。"
                    if lang == "zh"
                    else "Adjust in OS/NIC or the proxy client; do not disable the tunnel adapter by mistake. "
                    "This tool will not change routes/IPv6 automatically."
                ),
            )

    # Timezone follow node — optional help (manual only)
    region = (intended_region or "").strip().upper()
    geo = by_id.get("consistency.geo_stack")
    # pull country from reputation check evidence if any
    country = None
    for cid, c in by_id.items():
        if "reputation" in cid or "egress" in cid:
            ev = _field(c, "evidence", None) or []
            if isinstance(ev, list):
                for item in ev:
                    if isinstance(item, dict):
                        val = item.get("value")
                        if isinstance(val, dict) and val.get("country"):
                            country = str(val.get("country")).upper()
                            break
                    else:
                        val = getattr(item, "value", None)
                        if isinstance(val, dict) and val.get("country"):
                            country = str(val.get("country")).upper()
                            break
        if country:
            break
    target = region or country
    if target:
        add_action(
            "timezone",
            f"可选：时区与出口 {target} 对齐" if lang == "zh" else f"Optional: align timezone with exit {target}",
            (
                f"若你**希望**本机显示时区与当前节点/出口（{target}）一致，可在 Windows「时间和语言」中**手动**修改时区。"
                "这是可选个性化，不是防封保证；不改也可以。本工具不会自动改时区。"
                if lang == "zh"
                else f"If you want the OS timezone to match exit {target}, change it manually in Windows settings. "
                "Optional only — not an anti-ban measure. This tool will not change timezone for you."
            ),
        )
    elif geo and str(_field(geo, "status", "") or "") == "warning":
        add_action(
            "timezone",
            "可选：统一语言/时区显示" if lang == "zh" else "Optional: align locale/timezone display",
            (
                "语言字段不一致时，可按真实使用习惯在系统设置中统一；"
                "若你有固定出口地区偏好，也可手动让时区与常用节点地区一致。"
                "本工具不会自动改时区或语言。"
                if lang == "zh"
                else "Align locale/timezone manually for real use or preferred exit region. "
                "This tool will not change them automatically."
            ),
        )

    # Environment hygiene / light "wash" — optional, not unban
    for cid, title_zh, title_en in (
        ("privacy.local_device_id", "可选：本机 Claude 目录/设备残留清理", "Optional: local Claude path hygiene"),
        ("privacy.telemetry_cache", "可选：本机遥测/缓存清理", "Optional: local telemetry/cache hygiene"),
    ):
        c = by_id.get(cid)
        if c and str(_field(c, "status", "") or "") == "unknown":
            expl = str(_field(c, "explanation", "") or "")
            if "present" in expl.lower() or "存在" in expl or "path" in expl.lower():
                add_action(
                    "hygiene",
                    title_zh if lang == "zh" else title_en,
                    (
                        "可在备份后手动删除本机 Claude 相关目录/缓存（本地卫生）。"
                        "不能清除服务端标记，不是解封。"
                        "也可用官方隐私环境变量脚本（仅 3 个文档化变量）。"
                        "本工具不会自动清环境。"
                        if lang == "zh"
                        else "After backup, you may manually clear local Claude paths/caches. "
                        "Does not clear server marks or unban. "
                        "Privacy env script only sets documented opt-out vars. "
                        "This tool will not wipe the environment for you."
                    ),
                )

    # Multi-client conflict
    other = by_id.get("network.other_proxy_clients")
    if other and str(_field(other, "status", "") or "") == "unknown":
        add_action(
            "clients",
            "只保留一个主力梯子" if lang == "zh" else "Keep a single primary proxy client",
            (
                f"除 **{profile.get('primary')}** 外还检测到其它代理进程；建议退出不用的客户端，避免系统代理被抢。"
                if lang == "zh"
                else f"Other proxy processes besides **{profile.get('primary')}** were seen; quit extras."
            ),
        )

    return {
        "profile": profile,
        "client_tips": tips,
        "actions": actions,
        "lang": lang,
        "cli_agent": bool(cli_agent),
    }


def format_personal_section(guidance: Dict[str, Any], lang: Optional[str] = None) -> str:
    """Markdown section for the report."""
    lang = lang or guidance.get("lang") or "zh"
    lang = "en" if str(lang).lower().startswith("en") else "zh"
    profile = guidance.get("profile") or {}
    tips: Sequence[str] = guidance.get("client_tips") or []
    actions: Sequence[Dict[str, str]] = guidance.get("actions") or []
    cli_agent = bool(guidance.get("cli_agent"))

    lines: List[str] = []
    if lang == "zh":
        lines.extend(
            [
                "## 个性化（检测到的代理）",
                "",
                f"- **当前主力：** {profile.get('primary') or '未知'}",
                f"- **引擎/类型：** {profile.get('engine') or '未知'}",
                f"- **置信度：** {profile.get('confidence') or 'unknown'}",
            ]
        )
        if cli_agent:
            lines.append("- **检测到 CLI 端 Agent：** 是（Claude Code / Codex 类）")
        labs = profile.get("labels") or []
        if labs:
            lines.append(f"- **相关进程/客户端：** {', '.join(str(x) for x in labs)}")
        lines.extend(["", "### 针对该软件的操作提示", ""])
        for t in tips:
            lines.append(f"- {t}")
        lines.extend(
            [
                "",
                "### 可协助你手动处理的事项（需你确认后自己改）",
                "",
                "下列均为**建议**，覆盖：时区对齐节点/出口、本地环境卫生、DNS / 路由 / TUN / IPv6 / 系统代理。"
                "**不会自动修改**系统；改之前请自己确认。",
                "",
            ]
        )
        if not actions:
            lines.append("_当前没有额外个性化动作；主链路看起来按你的意图可用。_")
        else:
            for i, act in enumerate(actions, 1):
                lines.append(f"{i}. **{act.get('title', '')}** — {act.get('detail', '')}")
        lines.append("")
    else:
        lines.extend(
            [
                "## Personalized (detected proxy)",
                "",
                f"- **Primary:** {profile.get('primary') or 'unknown'}",
                f"- **Engine:** {profile.get('engine') or 'unknown'}",
                f"- **Confidence:** {profile.get('confidence') or 'unknown'}",
            ]
        )
        labs = profile.get("labels") or []
        if labs:
            lines.append(f"- **Related clients:** {', '.join(str(x) for x in labs)}")
        lines.extend(["", "### Tips for this client", ""])
        for t in tips:
            lines.append(f"- {t}")
        lines.extend(
            [
                "",
                "### Manual actions we can guide (you change them)",
                "",
                "Recommendations only: timezone align to exit/node, local hygiene, "
                "DNS / route / TUN / IPv6 / system proxy. **Nothing is applied automatically.**",
                "",
            ]
        )
        if not actions:
            lines.append("_No extra personalized actions right now._")
        else:
            for i, act in enumerate(actions, 1):
                lines.append(f"{i}. **{act.get('title', '')}** — {act.get('detail', '')}")
        lines.append("")
    return "\n".join(lines)


def collect_client_profile_check(data: dict, builder) -> None:
    """Emit a single informational check for the detected client profile."""
    from .analysis.common import evidence

    profile = detect_active_proxy(data)
    primary = profile.get("primary") or "unknown"
    conf = profile.get("confidence") or "low"
    status = "pass" if conf in ("high", "medium") and primary and "未识别" not in str(primary) else "unknown"
    labels = profile.get("labels") or []
    builder.add(
        "client.profile",
        "Active proxy client profile",
        "client",
        status,
        "info",
        (
            f"Detected primary client/engine: {primary}"
            + (f" (also: {', '.join(labels[1:3])})" if len(labels) > 1 else "")
            + f". Confidence={conf}."
        ),
        (
            "Personalized guidance in the report is based on this detection. "
            "All network/timezone/hygiene changes remain manual after your approval."
        ),
        evidence=[
            evidence(
                "client_profile",
                "active proxy profile",
                {
                    "primary": primary,
                    "engine": profile.get("engine"),
                    "confidence": conf,
                    "mihomo_process": profile.get("mihomo_process"),
                    "service_mode": profile.get("service_mode"),
                },
            )
        ],
    )
