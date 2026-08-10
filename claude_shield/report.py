"""Markdown report formatter and three-tier action classification.

Maps AuditCheck rows into Must fix / Optional consistency / Leave alone
per SKILL.md Report Format. Adds plain-language explanations so non-experts
can read jargon without losing technical IDs.

Pure presentation — no collector I/O.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

# Checks that indicate routing/DNS leak risk when not passing.
_LEAKISH_IDS = frozenset({
    "network.allow_lan",
    "network.dns",
    "network.dns_mode",
    "network.dns_hijack",
    "network.strict_route",
    "network.dns_physical_resolver",
    "network.teredo",
    "network.ipv6_binding",
    "network.dns_respect_rules",
})

# Non-leak consistency / preference signals.
_OPTIONAL_IDS = frozenset({
    "system.locale",
    "system.timezone",
    "network.tun",
    "network.tun_stack",
    "network.env_proxy",
    "network.dns_ipv6",
    "network.dns_encrypted",
    "privacy.telemetry",
    "privacy.errors",
    "privacy.nonessential",
    "privacy.prompt_history",
    "privacy.subprocess_scrub",
    "privacy.otel_user_prompts",
    "privacy.otel_tool_content",
    "privacy.otel_tool_details",
    "privacy.otel_raw_api",
})

_ACTION_ORDER = ("must_fix", "optional_consistency", "leave_alone")

# Technical section titles stay stable for agents; plain titles are added beside them.
_ACTION_TITLES = {
    "must_fix": "Must fix",
    "optional_consistency": "Optional consistency",
    "leave_alone": "Leave alone",
}
_ACTION_PLAIN = {
    "zh": {
        "must_fix": "必须处理（确认有问题，建议尽快改）",
        "optional_consistency": "可选一致性（不是泄漏，看你要不要统一）",
        "leave_alone": "保持不动（正常或无需处理）",
    },
    "en": {
        "must_fix": "Must fix (confirmed problem — change soon)",
        "optional_consistency": "Optional consistency (not a leak — tidy if you want)",
        "leave_alone": "Leave alone (healthy or no action needed)",
    },
}
_STATUS_PLAIN = {
    "zh": {
        "pass": "通过",
        "fail": "失败",
        "warning": "警告",
        "unknown": "未知/未验证",
        "skipped": "已跳过",
        "error": "出错",
    },
    "en": {
        "pass": "pass",
        "fail": "fail",
        "warning": "warning",
        "unknown": "unknown / not verified",
        "skipped": "skipped",
        "error": "error",
    },
}
_SEVERITY_MUST = frozenset({"medium", "high", "critical"})

# Plain-language meaning of each check id (what it is about — not the result).
_CHECK_PLAIN = {
    "zh": {
        "privacy.telemetry": "Claude 会不会把使用数据（埋点）发回去",
        "privacy.errors": "Claude 会不会自动上报错误日志",
        "privacy.nonessential": "是否关掉非必要的后台联网",
        "privacy.prompt_history": "是否少把对话记录长期留在本地（补充项，未配置不等于坏）",
        "privacy.subprocess_scrub": "子进程会不会继承敏感环境变量（补充项）",
        "privacy.otel_user_prompts": "监控系统会不会记下你的提问内容（补充项）",
        "privacy.otel_tool_content": "监控系统会不会记下工具调用内容（补充项）",
        "privacy.otel_tool_details": "监控系统会不会记下工具细节（补充项）",
        "privacy.otel_raw_api": "监控系统会不会记下原始 API 正文（补充项）",
        "network.service": "代理软件（Mihomo）是否在正常运行、端口是否在听",
        "network.teredo": "系统有没有开可能绕过代理的 IPv6 隧道（Teredo）",
        "network.ipv6_binding": "网卡 IPv6 会不会从物理网络直接出去",
        "network.dns_physical_resolver": "宽带/路由器 DNS 是否还配在物理网卡上（有 fake-IP 时通常无害）",
        "network.env_proxy": "系统/终端里有没有手动设置代理环境变量",
        "network.system_proxy": "Windows 系统代理是否打开，并指向本机代理端口",
        "network.other_proxy_clients": "有没有别的代理软件同时在跑、可能打架",
        "system.locale": "系统语言/地区设置是否互相一致",
        "system.timezone": "系统时区是什么",
        "browser.webrtc.chrome": "Chrome 有没有限制 WebRTC 暴露真实地址（策略层，非实测）",
        "browser.webrtc.edge": "Edge 有没有限制 WebRTC 暴露真实地址（策略层，非实测）",
        "browser.webrtc.firefox": "Firefox 有没有限制 WebRTC 暴露真实地址（策略层，非实测）",
        "network.mode": "代理是否工作在「规则模式」（按规则分流）",
        "network.allow_lan": "是否禁止局域网其它设备蹭你的代理端口",
        "network.tun": "是否开启虚拟网卡全隧道（TUN）；关着也可能只是系统代理模式",
        "network.strict_route": "严格路由：尽量让流量按隧道走、减少漏网",
        "network.dns": "代理是否接管 DNS 查询",
        "network.dns_mode": "是否使用 fake-IP（用假 IP 先占位，再走代理解析）",
        "network.dns_hijack": "是否劫持 53 端口 DNS，减少查询绕过代理",
        "network.dns_respect_rules": "DNS 是否也遵守分流规则",
        "network.dns_ipv6": "DNS 的 IPv6 开关是否和整体 IPv6 策略一致",
        "network.dns_encrypted": "上游 DNS 是否使用加密（如 DoH）",
        "network.tun_stack": "TUN 使用的网络栈类型（如 gvisor），本身不代表泄漏",
        "network.policy_group": "节点是否固定选择，而不是自动测速乱跳",
        "network.mihomo": "有没有读到 Mihomo/Clash 配置",
        "network.dns.consistency": "在线时观察 DNS 能否解析（不能单独证明泄漏）",
        "network.ip_reputation": "在线时出口 IP 的国家/运营商类标签（第三方看法，不是判决）",
        "network.cross_site.routing": "在线时多个网站看到的出口是否一致",
        "network.egress.probe_error": "在线探测没跑成",
    },
    "en": {
        "privacy.telemetry": "Whether Claude metrics telemetry is disabled",
        "privacy.errors": "Whether Claude error reporting is disabled",
        "privacy.nonessential": "Whether non-essential Claude background traffic is disabled",
        "privacy.prompt_history": "Optional: reduce local prompt-history persistence",
        "privacy.subprocess_scrub": "Optional: scrub secrets from subprocess environments",
        "privacy.otel_user_prompts": "Optional: whether OpenTelemetry logs user prompts",
        "privacy.otel_tool_content": "Optional: whether OpenTelemetry logs tool content",
        "privacy.otel_tool_details": "Optional: whether OpenTelemetry logs tool details",
        "privacy.otel_raw_api": "Optional: whether OpenTelemetry logs raw API bodies",
        "network.service": "Whether the Mihomo proxy process/service and port are up",
        "network.teredo": "Whether Teredo (an IPv6 tunnel that can bypass the proxy) is off",
        "network.ipv6_binding": "Whether physical NICs expose IPv6 that could bypass the tunnel",
        "network.dns_physical_resolver": "Whether ISP DNS is still configured on physical adapters",
        "network.env_proxy": "Whether HTTP(S)_PROXY environment variables are set",
        "network.system_proxy": "Whether Windows system proxy points at the local proxy port",
        "network.other_proxy_clients": "Whether other proxy apps are also running",
        "system.locale": "Whether Windows language/locale settings agree with each other",
        "system.timezone": "What timezone Windows is using",
        "browser.webrtc.chrome": "Chrome managed WebRTC policy only (not a live WebRTC test)",
        "browser.webrtc.edge": "Edge managed WebRTC policy only (not a live WebRTC test)",
        "browser.webrtc.firefox": "Firefox managed WebRTC policy only (not a live WebRTC test)",
        "network.mode": "Whether the proxy is in rule mode",
        "network.allow_lan": "Whether LAN devices are blocked from using your proxy port",
        "network.tun": "Whether full-tunnel TUN is on; off may mean system-proxy mode on purpose",
        "network.strict_route": "Strict routing to reduce traffic leaking off the tunnel",
        "network.dns": "Whether the proxy handles DNS lookups",
        "network.dns_mode": "Whether fake-IP DNS mode is enabled",
        "network.dns_hijack": "Whether port-53 DNS is hijacked into the proxy",
        "network.dns_respect_rules": "Whether DNS follows the same routing rules",
        "network.dns_ipv6": "Whether DNS IPv6 matches the IPv6 routing toggle",
        "network.dns_encrypted": "Whether upstream DNS uses encryption (e.g. DoH)",
        "network.tun_stack": "Which TUN stack is used (informational)",
        "network.policy_group": "Whether the node is pinned instead of auto-switching",
        "network.mihomo": "Whether Mihomo/Clash config was available",
        "network.dns.consistency": "Online DNS resolve observation (not leak proof alone)",
        "network.ip_reputation": "Online exit IP labels from third parties (opinion, not verdict)",
        "network.cross_site.routing": "Online check that several sites see a consistent exit",
        "network.egress.probe_error": "Online probes failed to run",
    },
}

_GLOSSARY = {
    "zh": [
        ("pass / 通过", "这项看起来正常。"),
        ("fail / 失败", "确认有问题，应处理。"),
        ("warning / 警告", "有风险或不一致，需要你看一眼。"),
        ("unknown / 未知", "证据不够，不能当成「安全」也不能当成「泄漏」。"),
        ("Must fix / 必须处理", "已确认的问题或高风险项。"),
        ("Optional consistency / 可选一致性", "不影响「有没有漏」，只是风格/习惯是否统一。"),
        ("Leave alone / 保持不动", "正常，或改了也没好处。"),
        ("Mihomo / Clash", "常见代理核心/客户端（如 Clash Verge 用的引擎）。"),
        ("系统代理 (system proxy)", "让软件走系统里填的代理地址（通常是 127.0.0.1:端口）。"),
        ("TUN / 全隧道", "虚拟网卡模式，更多流量强制进代理；比「仅系统代理」覆盖面更大。"),
        ("fake-IP", "DNS 先返回假 IP，真正访问时再走代理解析，便于接管查询。"),
        ("DNS 劫持 (port 53)", "把系统 DNS 查询拦到代理里，减少「查网站直接问宽带运营商」。"),
        ("DoH / 加密 DNS", "DNS 查询加密传输，减少被中间人偷看域名。"),
        ("strict-route", "严格路由，减少流量从旁路溜走。"),
        ("Teredo", "一种 IPv6 隧道，有时会绕过你的代理，一般建议关掉。"),
        ("WebRTC", "浏览器实时通讯技术；配置不当可能暴露真实网络地址。本工具默认只看策略，不做网页实测。"),
        ("策略组 / policy group", "代理里选节点的分组；固定选择比自动测速乱跳更稳。"),
        ("not_configured", "这项开关根本没配，不等于已经泄漏。"),
    ],
    "en": [
        ("pass", "Looks healthy for this check."),
        ("fail", "Confirmed problem — act on it."),
        ("warning", "Risk or mismatch — review it."),
        ("unknown", "Not enough evidence; neither safe nor a proven leak."),
        ("Must fix", "Confirmed issues or high-risk items."),
        ("Optional consistency", "Not a leak; tidy only if you want consistency."),
        ("Leave alone", "Fine as-is, or changing it does not help."),
        ("Mihomo / Clash", "Common proxy engine/client stack."),
        ("System proxy", "Apps use the OS proxy address (usually 127.0.0.1:port)."),
        ("TUN", "Virtual-adapter full-tunnel mode; broader capture than system proxy alone."),
        ("fake-IP", "DNS returns placeholder IPs so lookups can be steered through the proxy."),
        ("DNS hijack (port 53)", "Forces DNS queries into the proxy path."),
        ("DoH", "Encrypted DNS so names are harder to snoop on the wire."),
        ("strict-route", "Tightens routing so fewer packets bypass the tunnel."),
        ("Teredo", "An IPv6 transition tunnel that can bypass the proxy; usually keep off."),
        ("WebRTC", "Browser realtime API; bad settings can expose real addresses. This tool only reads policy by default."),
        ("Policy group", "How nodes are chosen; fixed manual selection is stabler than auto URL-test."),
        ("not_configured", "The optional control is absent — not proof of a leak."),
    ],
}


def _field(check: Any, name: str, default: Any = None) -> Any:
    if isinstance(check, Mapping):
        return check.get(name, default)
    return getattr(check, name, default)


def _norm_lang(lang: Optional[str]) -> str:
    value = (lang or "zh").strip().lower()
    if value in ("en", "english"):
        return "en"
    return "zh"


def plain_status(status: str, lang: str = "zh") -> str:
    lang = _norm_lang(lang)
    key = str(status or "").lower()
    return _STATUS_PLAIN.get(lang, _STATUS_PLAIN["zh"]).get(key, str(status or ""))


def plain_action(action: str, lang: str = "zh") -> str:
    lang = _norm_lang(lang)
    return _ACTION_PLAIN.get(lang, _ACTION_PLAIN["zh"]).get(action, action)


def plain_check(check_id: str, lang: str = "zh") -> str:
    """Return a one-line plain explanation of what this check means."""
    lang = _norm_lang(lang)
    table = _CHECK_PLAIN.get(lang, _CHECK_PLAIN["zh"])
    check_id = str(check_id or "")
    if check_id in table:
        return table[check_id]
    # prefix fallbacks for dynamic ids
    if check_id.startswith("network.egress.runtime_consistency"):
        return (
            "在线对比不同方式看到的出口是否一致"
            if lang == "zh"
            else "Online: whether different runtimes see the same egress"
        )
    if check_id.startswith("browser.webrtc."):
        return (
            "浏览器 WebRTC 策略（不是网页实测）"
            if lang == "zh"
            else "Browser WebRTC policy only (not a live page test)"
        )
    return (
        "本项检查的技术细节见上方英文/原始说明"
        if lang == "zh"
        else "See the technical explanation above"
    )


def status_reason(check: Any) -> str:
    """Return a short subtype tag for unknown/optional checks.

    Encoded in explanation as ``[not_configured] ...`` when applicable;
    otherwise empty. Does not alter the AuditCheck schema.
    """
    explanation = str(_field(check, "explanation", "") or "")
    stripped = explanation.lstrip()
    if stripped.startswith("[") and "]" in stripped:
        tag = stripped[1:stripped.index("]")]
        if tag:
            return tag
    confidence = str(_field(check, "confidence", "") or "")
    status = str(_field(check, "status", "") or "")
    if status == "unknown" and confidence == "unknown":
        check_id = str(_field(check, "id", "") or "")
        if check_id.startswith("privacy."):
            return "not_configured"
    return ""


def classify_action(check: Any) -> str:
    """Classify a check into must_fix | optional_consistency | leave_alone."""
    status = str(_field(check, "status", "") or "")
    severity = str(_field(check, "severity", "info") or "info")
    check_id = str(_field(check, "id", "") or "")
    explanation = str(_field(check, "explanation", "") or "")
    reason = status_reason(check)

    if status == "fail":
        return "must_fix"
    if status == "warning" and severity in _SEVERITY_MUST:
        return "must_fix"
    if status in ("fail", "warning") and check_id in _LEAKISH_IDS:
        return "must_fix"

    if check_id in ("system.locale", "system.timezone"):
        if status == "pass":
            return "leave_alone"
        return "optional_consistency"

    if check_id == "network.tun" and status in ("unknown", "warning"):
        return "optional_consistency"

    if reason == "not_configured" or "[not_configured]" in explanation:
        return "optional_consistency"

    if check_id in _OPTIONAL_IDS and status in ("unknown", "warning"):
        return "optional_consistency"

    if status == "pass":
        return "leave_alone"

    if status == "warning" and severity in ("low", "info"):
        if check_id not in _LEAKISH_IDS:
            return "optional_consistency"

    if status in ("unknown", "skipped"):
        return "leave_alone"

    return "leave_alone"


def group_checks(checks: Iterable[Any]) -> Dict[str, List[Any]]:
    """Group checks by classify_action() result."""
    groups: Dict[str, List[Any]] = {key: [] for key in _ACTION_ORDER}
    for check in checks:
        action = classify_action(check)
        if action not in groups:
            action = "leave_alone"
        groups[action].append(check)
    return groups



def score_checks(checks: Iterable[Any]) -> Dict[str, Any]:
    """Compute a 0-100 audit score from classified checks.

    Starts at 100 and subtracts weighted penalties. Floor 0, ceiling 100.
    """
    checks = list(checks or [])
    score = 100
    breakdown = {
        "must_fix_penalty": 0,
        "optional_penalty": 0,
        "incomplete_penalty": 0,
        "must_fix": 0,
        "optional_consistency": 0,
        "leave_alone": 0,
    }
    deductions = []

    for check in checks:
        action = classify_action(check)
        status = str(_field(check, "status", "") or "").lower()
        severity = str(_field(check, "severity", "info") or "info").lower()
        check_id = str(_field(check, "id", "") or "")
        reason = status_reason(check)
        breakdown[action] = breakdown.get(action, 0) + 1

        penalty = 0
        if action == "must_fix":
            if status == "fail":
                penalty = 18
            elif status == "warning":
                penalty = 14
            else:
                penalty = 10
            if severity == "medium":
                penalty += 2
            elif severity == "high":
                penalty += 4
            elif severity == "critical":
                penalty += 6
            breakdown["must_fix_penalty"] += penalty
        elif action == "optional_consistency":
            if reason == "not_configured" or check_id.startswith("privacy.otel") or check_id in (
                "privacy.prompt_history",
                "privacy.subprocess_scrub",
            ):
                penalty = 1
            elif status == "warning":
                penalty = 3
            elif status == "unknown":
                penalty = 2
            else:
                penalty = 1
            breakdown["optional_penalty"] += penalty
        elif action == "leave_alone" and status == "unknown" and check_id in _LEAKISH_IDS:
            penalty = 1
            breakdown["incomplete_penalty"] += penalty

        if penalty:
            score -= penalty
            deductions.append({
                "id": check_id,
                "action": action,
                "status": status,
                "penalty": penalty,
            })

    score = max(0, min(100, int(score)))
    if score >= 90:
        grade, label_zh, label_en = "A", "优秀", "Excellent"
    elif score >= 75:
        grade, label_zh, label_en = "B", "良好", "Good"
    elif score >= 60:
        grade, label_zh, label_en = "C", "一般", "Fair"
    else:
        grade, label_zh, label_en = "D", "较差", "Poor"

    return {
        "score": score,
        "max_score": 100,
        "grade": grade,
        "label_zh": label_zh,
        "label_en": label_en,
        "breakdown": breakdown,
        "deductions": deductions,
    }


def _evidence_cell(check: Any) -> str:
    items = _field(check, "evidence", None) or []
    if not items:
        return "—"
    parts = []
    for item in items[:3]:
        if isinstance(item, Mapping):
            desc = item.get("description") or item.get("type") or ""
        else:
            desc = getattr(item, "description", None) or getattr(item, "type", "") or ""
        desc = str(desc).replace("|", "/").strip()
        if desc:
            parts.append(desc)
    return "; ".join(parts) if parts else "—"


def _md_escape_cell(value: Any) -> str:
    text = str(value if value is not None else "").replace("\n", " ").replace("|", "/")
    return text.strip() or "—"



def _intro_lines(lang: str) -> List[str]:
    if lang == "en":
        return [
            "Local evidence only — not a prediction of account review or bans.",
            "",
        ]
    return [
        "本机检查结果，不是「账号会不会被封」的预测。",
        "",
    ]



def _glossary_lines(lang: str) -> List[str]:
    title = "## Glossary" if lang == "en" else "## 名词解释"
    lines = [title, ""]
    lines.append("| term | meaning |" if lang == "en" else "| 名词 | 含义 |")
    lines.append("| --- | --- |")
    for term, meaning in _GLOSSARY.get(lang, _GLOSSARY["zh"]):
        lines.append(
            "| {t} | {m} |".format(
                t=_md_escape_cell(term),
                m=_md_escape_cell(meaning),
            )
        )
    lines.append("")
    return lines


def _signal_label(check: Any) -> str:
    check_id = str(_field(check, "id", "") or "")
    check_title = str(_field(check, "title", "") or "").strip()
    if check_title and check_id and check_title != check_id:
        return f"{check_title} (`{check_id}`)"
    return check_title or check_id or "—"


def _row_cells(check: Any, lang: str) -> Dict[str, str]:
    check_id = str(_field(check, "id", "") or "")
    status = str(_field(check, "status", "") or "")
    action = classify_action(check)
    explanation = str(_field(check, "explanation", "") or "").strip()
    recommendation = str(_field(check, "recommendation", "") or "").strip()
    if explanation.startswith("[") and "]" in explanation:
        # strip tags like [not_configured] for cleaner table detail
        tag_end = explanation.index("]")
        rest = explanation[tag_end + 1 :].strip()
        if rest:
            explanation = rest
    return {
        "item": _signal_label(check),
        "status": f"{plain_status(status, lang)} ({status})" if status else "—",
        "meaning": plain_check(check_id, lang),
        "detail": explanation or "—",
        "group": plain_action(action, lang),
        "action_key": action,
        "recommendation": recommendation,
    }


def format_report(
    checks: Sequence[Any],
    summary: Optional[Mapping[str, Any]] = None,
    lang: str = "zh",
) -> str:
    """Render checks as markdown tables for AI/chat display.

    Plain-language text lives in table columns (说明 / meaning). Plain meaning is a normal table column.
    """
    lang = _norm_lang(lang)
    checks = list(checks or [])
    lines: List[str] = ["# Claude Shield Audit Report", ""]
    lines.extend(_intro_lines(lang))

    groups = group_checks(checks)
    scored = score_checks(checks)
    if lang == "zh":
        lines.extend([
            "## 评分",
            "",
            "| 项目 | 值 |",
            "| --- | --- |",
            f"| 得分 | **{scored['score']}** / {scored['max_score']} |",
            f"| 等级 | {scored['grade']}（{scored['label_zh']}） |",
            f"| 必须处理扣分 | -{scored['breakdown']['must_fix_penalty']}（{scored['breakdown']['must_fix']} 项） |",
            f"| 可选一致性扣分 | -{scored['breakdown']['optional_penalty']}（{scored['breakdown']['optional_consistency']} 项） |",
            f"| 证据不足扣分 | -{scored['breakdown']['incomplete_penalty']} |",
            "",
            "_满分 100。必须处理扣得多，可选一致性扣得少；未配置的补充隐私项只扣 1 分。_",
            "",
        ])
    else:
        lines.extend([
            "## Score",
            "",
            "| item | value |",
            "| --- | --- |",
            f"| score | **{scored['score']}** / {scored['max_score']} |",
            f"| grade | {scored['grade']} ({scored['label_en']}) |",
            f"| must-fix penalty | -{scored['breakdown']['must_fix_penalty']} ({scored['breakdown']['must_fix']} items) |",
            f"| optional penalty | -{scored['breakdown']['optional_penalty']} ({scored['breakdown']['optional_consistency']} items) |",
            f"| incomplete evidence | -{scored['breakdown']['incomplete_penalty']} |",
            "",
            "_Out of 100. Must-fix costs more than optional consistency; not_configured privacy add-ons cost 1 each._",
            "",
        ])


    if lang == "zh":
        lines.extend(
            [
                "## 全部结果",
                "",
                "| 检查项 | 状态 | 说明 | 详情 | 分组 | 建议 |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
    else:
        lines.extend(
            [
                "## All results",
                "",
                "| check | status | meaning | detail | group | recommendation |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )

    for check in checks:
        row = _row_cells(check, lang)
        rec = row["recommendation"] if row["action_key"] != "leave_alone" else ""
        lines.append(
            "| {item} | {status} | {meaning} | {detail} | {group} | {rec} |".format(
                item=_md_escape_cell(row["item"]),
                status=_md_escape_cell(row["status"]),
                meaning=_md_escape_cell(row["meaning"]),
                detail=_md_escape_cell(row["detail"]),
                group=_md_escape_cell(row["group"]),
                rec=_md_escape_cell(rec or "—"),
            )
        )
    lines.append("")

    section_titles = {
        "zh": {
            "must_fix": "## 必须处理",
            "optional_consistency": "## 可选一致性",
            "leave_alone": "## 保持不动",
        },
        "en": {
            "must_fix": "## Must fix",
            "optional_consistency": "## Optional consistency",
            "leave_alone": "## Leave alone",
        },
    }
    head = (
        (
            "| 检查项 | 状态 | 说明 | 详情 | 建议 |",
            "| --- | --- | --- | --- | --- |",
        )
        if lang == "zh"
        else (
            "| check | status | meaning | detail | recommendation |",
            "| --- | --- | --- | --- | --- |",
        )
    )

    for key in _ACTION_ORDER:
        lines.append(section_titles[lang][key])
        lines.append("")
        items = groups.get(key) or []
        if not items:
            lines.append("_无。_" if lang == "zh" else "_None._")
            lines.append("")
            continue
        lines.append(head[0])
        lines.append(head[1])
        for check in items:
            row = _row_cells(check, lang)
            rec = "—" if key == "leave_alone" else (row["recommendation"] or "—")
            lines.append(
                "| {item} | {status} | {meaning} | {detail} | {rec} |".format(
                    item=_md_escape_cell(row["item"]),
                    status=_md_escape_cell(row["status"]),
                    meaning=_md_escape_cell(row["meaning"]),
                    detail=_md_escape_cell(row["detail"]),
                    rec=_md_escape_cell(rec),
                )
            )
        lines.append("")

    lines.extend(_glossary_lines(lang))
    if lang == "zh":
        lines.append("_不确定就会标明。第三方评分和静态配置，都不能单独当成「泄漏证据」。_")
    else:
        lines.append(
            "_Uncertainty is stated explicitly. Reputation scores and static "
            "configuration alone are not proof of a leak._"
        )
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "classify_action",
    "format_report",
    "group_checks",
    "score_checks",
    "plain_action",
    "plain_check",
    "plain_status",
    "status_reason",
]
