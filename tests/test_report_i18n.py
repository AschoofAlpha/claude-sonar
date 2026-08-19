"""zh localization of detail/recommendation + compact format_report."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_sonar.models import AuditCheck
from claude_sonar.report import (
    format_report,
    translate_detail,
    translate_recommendation,
)


def _check(**kwargs):
    defaults = dict(
        id="x.test",
        title="t",
        category="network",
        status="pass",
        severity="info",
        confidence="confirmed",
        explanation="",
        recommendation="",
    )
    defaults.update(kwargs)
    return AuditCheck(**defaults)


class TestTranslateDetail(unittest.TestCase):
    def test_en_passthrough(self):
        src = "Observed TunEnabled=False. System proxy may be intentional."
        self.assertEqual(translate_detail(src, "en"), src)

    def test_observed_tunenabled(self):
        out = translate_detail("Observed TunEnabled=False.", "zh")
        self.assertIn("观察到", out)
        self.assertIn("TunEnabled", out)
        self.assertIn("False", out)
        self.assertNotIn("Observed ", out)

    def test_was_not_observed(self):
        out = translate_detail(
            "CLAUDE_CODE_SKIP_PROMPT_HISTORY was not observed.", "zh"
        )
        self.assertIn("未被观察到", out)
        self.assertIn("CLAUDE_CODE_SKIP_PROMPT_HISTORY", out)

    def test_system_proxy_loopback(self):
        out = translate_detail(
            "System proxy is enabled and points to loopback.", "zh"
        )
        self.assertIn("系统代理", out)
        self.assertIn("回环", out)
        self.assertNotIn("System proxy is enabled", out)

    def test_optional_recommendation_phrase(self):
        out = translate_recommendation(
            "OPTIONAL RECOMMENDATION ONLY — never auto-applied: clear local caches.",
            "zh",
        )
        self.assertTrue(
            "仅可选建议" in out or "绝不会自动执行" in out,
            msg=out,
        )
        self.assertNotIn("OPTIONAL RECOMMENDATION ONLY", out)

    def test_physical_adapter(self):
        out = translate_detail(
            "Physical adapter DNS resolver(s) are configured, but fake-IP plus port-53 hijack is on.",
            "zh",
        )
        self.assertIn("物理网卡", out)

    def test_is_active(self):
        out = translate_detail("PAC/WPAD auto-config is active on this host.", "zh")
        self.assertIn("处于活动状态", out)

    def test_format_report_zh_translates_detail_and_rec(self):
        checks = [
            _check(
                id="network.tun",
                status="unknown",
                confidence="unknown",
                explanation="Observed TunEnabled=False. System-proxy mode may be intentional; "
                "confirm the intended mode rather than treating TUN-off as an automatic failure.",
                recommendation="Only enable TUN if it matches the intended routing mode; "
                "system-proxy alone is not a leak.",
            ),
            _check(
                id="network.allow_lan",
                status="warning",
                severity="low",
                confidence="probable",
                explanation="Observed AllowLan=True.",
                recommendation="Confirm the setting in the active proxy client before changing it.",
            ),
        ]
        md = format_report(checks, lang="zh")
        self.assertIn("观察到", md)
        self.assertIn("TunEnabled", md)
        # recommendation localized in must/optional sections
        self.assertIn("更改前请先在当前代理客户端中确认该设置", md)
        self.assertNotIn("Confirm the setting in the active proxy client before changing it.", md)

    def test_format_report_en_keeps_english_detail(self):
        checks = [
            _check(
                id="network.tun",
                status="unknown",
                confidence="unknown",
                explanation="Observed TunEnabled=False.",
                recommendation="Only enable TUN if it matches the intended routing mode.",
            ),
        ]
        md = format_report(checks, lang="en")
        self.assertIn("Observed TunEnabled=False.", md)
        self.assertIn("Only enable TUN if it matches the intended routing mode.", md)


class TestCompactFormat(unittest.TestCase):
    def test_compact_omits_all_results_and_leave_alone(self):
        checks = [
            _check(
                id="network.allow_lan",
                status="fail",
                severity="high",
                explanation="Observed AllowLan=True.",
                recommendation="Confirm the setting.",
            ),
            _check(
                id="system.locale",
                status="warning",
                severity="info",
                confidence="probable",
                explanation="Culture/UICulture/SystemLocale differ.",
            ),
            _check(id="network.mode", status="pass", explanation="Observed Mode='Rule'."),
        ]
        md = format_report(checks, lang="zh", compact=True)
        self.assertIn("## 配置自洽分", md)
        self.assertIn("## 必须处理", md)
        self.assertIn("## 可选一致性", md)
        self.assertNotIn("## 全部结果", md)
        self.assertNotIn("## 保持不动", md)
        self.assertNotIn("## 名词解释", md)
        # footer still present
        self.assertIn("## 本工具如何协助你改配置", md)
        self.assertIn("network.allow_lan", md)

    def test_full_still_has_all_results(self):
        checks = [
            _check(id="network.mode", status="pass", explanation="Observed Mode='Rule'."),
        ]
        md = format_report(checks, lang="zh", compact=False, include_all_results=True)
        self.assertIn("## 全部结果", md)
        self.assertIn("## 保持不动", md)
        self.assertIn("## 名词解释", md)

    def test_default_omits_all_results(self):
        checks = [
            _check(id="network.mode", status="pass", explanation="Observed Mode='Rule'."),
        ]
        md = format_report(checks, lang="zh", compact=False)
        self.assertNotIn("## 全部结果", md)
        self.assertIn("## 保持不动", md)

    def test_compact_en(self):
        md = format_report(
            [_check(id="network.mode", status="pass")],
            lang="en",
            compact=True,
        )
        self.assertNotIn("## All results", md)
        self.assertNotIn("## Leave alone", md)
        self.assertIn("## Must fix", md)
        self.assertIn("## Optional consistency", md)
        self.assertIn("## How this tool helps you change settings", md)


if __name__ == "__main__":
    unittest.main()
