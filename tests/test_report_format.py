import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_shield.analyze import analyze_snapshot
from claude_shield.models import AuditCheck, Evidence
from claude_shield.report import classify_action, format_report, group_checks, score_checks, status_reason


def _check(**kwargs):
    defaults = dict(
        id="x.test",
        title="t",
        category="network",
        status="pass",
        severity="info",
        confidence="confirmed",
        explanation="",
    )
    defaults.update(kwargs)
    return AuditCheck(**defaults)


class TestReportFormat(unittest.TestCase):
    def test_classify_fail_is_must_fix(self):
        self.assertEqual(classify_action(_check(status="fail", severity="info")), "must_fix")

    def test_classify_high_warning_is_must_fix(self):
        self.assertEqual(
            classify_action(_check(status="warning", severity="high", id="network.other")),
            "must_fix",
        )

    def test_classify_leakish_low_warning_is_must_fix(self):
        self.assertEqual(
            classify_action(_check(
                id="network.dns_hijack",
                status="warning",
                severity="low",
                confidence="probable",
                explanation="Observed DnsHijackAny53=False.",
            )),
            "must_fix",
        )

    def test_classify_locale_warning_optional(self):
        self.assertEqual(
            classify_action(_check(
                id="system.locale",
                status="warning",
                severity="info",
                confidence="probable",
                explanation="Culture/UICulture/SystemLocale differ.",
            )),
            "optional_consistency",
        )

    def test_classify_timezone_pass_leave_alone(self):
        self.assertEqual(
            classify_action(_check(id="system.timezone", status="pass", explanation="TimeZone is UTC.")),
            "leave_alone",
        )

    def test_classify_timezone_unknown_optional(self):
        self.assertEqual(
            classify_action(_check(
                id="system.timezone",
                status="unknown",
                confidence="unknown",
                explanation="TimeZone information is missing.",
            )),
            "optional_consistency",
        )

    def test_classify_tun_off_optional(self):
        self.assertEqual(
            classify_action(_check(
                id="network.tun",
                status="unknown",
                confidence="unknown",
                explanation="Observed TunEnabled=False. System-proxy mode may be intentional.",
            )),
            "optional_consistency",
        )

    def test_classify_not_configured_privacy_optional(self):
        self.assertEqual(
            classify_action(_check(
                id="privacy.prompt_history",
                status="unknown",
                confidence="unknown",
                explanation="[not_configured] CLAUDE_CODE_SKIP_PROMPT_HISTORY was not observed.",
            )),
            "optional_consistency",
        )

    def test_classify_pass_leave_alone(self):
        self.assertEqual(
            classify_action(_check(id="network.mode", status="pass", explanation="Observed Mode='Rule'.")),
            "leave_alone",
        )

    def test_status_reason_from_prefix(self):
        self.assertEqual(
            status_reason(_check(
                status="unknown",
                confidence="unknown",
                explanation="[not_configured] x was not observed.",
            )),
            "not_configured",
        )

    def test_group_checks_keys(self):
        checks = [
            _check(id="a", status="fail", severity="high"),
            _check(id="system.locale", status="warning", severity="info", confidence="probable"),
            _check(id="b", status="pass"),
        ]
        groups = group_checks(checks)
        self.assertEqual(set(groups), {"must_fix", "optional_consistency", "leave_alone"})
        self.assertEqual(len(groups["must_fix"]), 1)
        self.assertEqual(len(groups["optional_consistency"]), 1)
        self.assertEqual(len(groups["leave_alone"]), 1)

    def test_format_report_markdown_structure(self):
        checks = [
            _check(
                id="network.dns_hijack",
                status="warning",
                severity="low",
                confidence="probable",
                explanation="Observed DnsHijackAny53=False.",
                evidence=[Evidence(type="mihomo_config", description="DnsHijackAny53", data=False)],
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
        md = format_report(checks, summary={"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 2}, lang="zh")
        self.assertIn("# Claude Shield Audit Report", md)
        self.assertIn("| 检查项 | 状态 | 说明 | 详情 | 分组 | 建议 |", md)
        self.assertIn("## 必须处理", md)
        self.assertIn("## 可选一致性", md)
        self.assertIn("## 保持不动", md)
        self.assertIn("network.dns_hijack", md)
        self.assertIn("## 全部结果", md)
        self.assertIn("名词解释", md)
        self.assertNotIn("人话", md)
        self.assertNotIn("plain:", md)
        self.assertIn("通过", md)

    def test_format_report_english_plain_layer(self):
        md = format_report([
            _check(id="network.tun", status="unknown", confidence="unknown",
                   explanation="Observed TunEnabled=False."),
        ], lang="en")
        self.assertIn("## All results", md)
        self.assertIn("| check | status | meaning | detail | group | recommendation |", md)
        self.assertIn("Glossary", md)
        self.assertNotIn("plain:", md)
        self.assertIn("full-tunnel TUN", md)

    def test_format_report_from_live_analysis(self):
        checks = analyze_snapshot({
            "Mihomo": {
                "AppConfigPresent": True,
                "Mode": "Rule",
                "AllowLan": True,
                "TunEnabled": False,
                "DnsEnabled": True,
                "DnsMode": "fake-ip",
                "DnsHijackAny53": True,
                "EncryptedDnsUpstreams": {"Scheme": "https"},
            },
            "System": {
                "TimeZone": "China Standard Time",
                "Culture": "en-US",
                "UICulture": "zh-CN",
                "SystemLocale": "zh-CN",
            },
            "ClaudeCode": {},
        })
        md = format_report(checks)
        self.assertIn("## 必须处理", md)
        self.assertIn("network.allow_lan", md)
        self.assertIn("network.tun", md)
        self.assertIn("system.timezone", md)
        # Tun off should not appear under Must fix
        groups = group_checks(checks)
        tun = next(c for c in checks if c.id == "network.tun")
        self.assertEqual(classify_action(tun), "optional_consistency")
        self.assertIn(tun, groups["optional_consistency"])


    def test_score_perfect_and_must_fix(self):
        perfect = [_check(id="network.mode", status="pass", explanation="ok")]
        s = score_checks(perfect)
        self.assertEqual(s["score"], 100)
        self.assertEqual(s["grade"], "A")
        bad = [_check(
            id="network.allow_lan",
            status="warning",
            severity="low",
            confidence="probable",
            explanation="AllowLan true",
        )]
        s2 = score_checks(bad)
        self.assertLess(s2["score"], 100)
        self.assertGreaterEqual(s2["score"], 0)
        md = format_report(bad, lang="zh")
        self.assertIn("## 配置自洽分", md)
        self.assertIn("/ 100", md)
        self.assertNotIn("## 防封", md)


if __name__ == "__main__":
    unittest.main()
