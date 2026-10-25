"""Claude Code settings.json deny list and Desktop locale vs system UI languages."""

from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence


def _lang_prefix(tag: Any) -> str:
    text = str(tag or "").strip()
    if not text:
        return ""
    return text.replace("_", "-").split("-", 1)[0].lower()


def collect_settings_deny_check(claude: Mapping[str, Any], builder) -> None:
    present = claude.get("SettingsJsonPresent")
    count = claude.get("SettingsDenyCount")
    try:
        count_i = int(count) if count is not None else None
    except (TypeError, ValueError):
        count_i = None
    if present is False or (present is None and count_i is None):
        builder.add(
            "privacy.settings_deny",
            "Claude Code permissions.deny",
            "privacy",
            "unknown",
            "info",
            "没有读到 settings.json，无法确认 permissions.deny 是否存在。",
            "换号或清空配置后，可把 .env / 密钥文件写进 permissions.deny。",
        )
        return
    if count_i and count_i > 0:
        builder.add(
            "privacy.settings_deny",
            "Claude Code permissions.deny",
            "privacy",
            "pass",
            "info",
            f"settings.json 里有 {count_i} 条 permissions.deny（只计条数，不读规则内容）。",
            "",
        )
        return
    builder.add(
        "privacy.settings_deny",
        "Claude Code permissions.deny",
        "privacy",
        "unknown",
        "info",
        "settings.json 在，但 permissions.deny 为空或未配置。",
        "需要拦密钥文件时，加上 Read(.env) / *.pem / credentials 一类 deny 规则。",
    )


def collect_desktop_locale_check(data: Mapping[str, Any], builder) -> None:
    system = data.get("System") if isinstance(data.get("System"), dict) else {}
    desktop = data.get("ClaudeDesktop") if isinstance(data.get("ClaudeDesktop"), dict) else {}
    preferred = system.get("PreferredUILanguages")
    if not isinstance(preferred, list):
        langs = system.get("UserLanguageList")
        preferred = langs if isinstance(langs, list) else []
    preferred_tags = [str(item) for item in preferred if item]
    primary = preferred_tags[0] if preferred_tags else ""
    config_present = desktop.get("ConfigPresent")
    config_locale = str(desktop.get("ConfigLocale") or "").strip()

    if config_present is False or (not config_present and not config_locale):
        builder.add(
            "system.desktop_locale",
            "Claude Desktop locale vs system UI languages",
            "system",
            "unknown",
            "info",
            "没有读到 Claude Desktop 的 config.json，无法对照界面语言来源。",
            "",
        )
        return

    cfg_prefix = _lang_prefix(config_locale)
    sys_prefix = _lang_prefix(primary)
    if not cfg_prefix or not sys_prefix:
        builder.add(
            "system.desktop_locale",
            "Claude Desktop locale vs system UI languages",
            "system",
            "unknown",
            "info",
            "Desktop locale 或系统 PreferredUILanguages 不完整。",
            "",
        )
        return
    if cfg_prefix == sys_prefix:
        builder.add(
            "system.desktop_locale",
            "Claude Desktop locale vs system UI languages",
            "system",
            "pass",
            "info",
            f"config.json locale={config_locale} 与系统首选 UI 语言 {primary} 一致。",
            "",
        )
        return
    builder.add(
        "system.desktop_locale",
        "Claude Desktop locale vs system UI languages",
        "system",
        "warning",
        "info",
        (
            f"config.json locale={config_locale}，但系统 PreferredUILanguages 首选是 {primary}。"
            "Electron 按系统 UI 语言列表选界面，只改 config.json 会被盖掉。"
        ),
        "要英文界面时，把 PreferredUILanguages 改成 en-US，并清 Desktop Local Storage 后再开。",
    )
