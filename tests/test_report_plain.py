"""Plain-language report layer + recommend-only footer + consistency score naming."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_shield.models import AuditCheck
from claude_shield.report import format_report, plain_check, score_checks


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


class TestReportPlain(unittest.TestCase):
    def test_plain_check_known_ids(self):
        zh = plain_check("network.dns", "zh")
        en = plain_check("network.dns", "en")
        self.assertTrue(zh)
        self.assertTrue(en)
        self.assertNotEqual(zh, en)
        self.assertIn("DNS", zh)

    def test_plain_check_prefix_fallbacks(self):
        cases = [
            ("network.egress.runtime_consistency.foo", "出口", "egress"),
            ("network.egress.something_new", "出口", "egress"),
            ("network.dns.future_probe", "DNS", "DNS"),
            ("network.cross_site.future", "跨站", "Cross-site"),
            ("network.ip_future_label", "IP", "IP"),
            ("network.brand_new_knob", "代理", "Proxy"),
            ("browser.webrtc.brave", "WebRTC", "WebRTC"),
            ("browser.cookies.future", "浏览器", "Browser"),
            ("privacy.future_knob", "隐私", "Privacy"),
            ("system.future_locale", "系统", "OS"),
            ("consistency.future_signal", "自洽", "consistency"),
        ]
        for check_id, zh_token, en_token in cases:
            zh = plain_check(check_id, "zh")
            en = plain_check(check_id, "en")
            self.assertTrue(zh.strip(), msg=f"empty zh for {check_id}")
            self.assertTrue(en.strip(), msg=f"empty en for {check_id}")
            self.assertIn(zh_token, zh, msg=f"{check_id} zh missing {zh_token!r}: {zh}")
            self.assertIn(en_token, en, msg=f"{check_id} en missing {en_token!r}: {en}")

    def test_plain_check_generic_future_fallback_dejargons(self):
        zh = plain_check("future.namespace.weird_metric", "zh")
        en = plain_check("future.namespace.weird_metric", "en")
        self.assertIn("weird metric", zh.lower().replace("「", "").replace("」", ""))
        self.assertIn("weird metric", en.lower())
        self.assertIn("不是防封", zh)
        self.assertIn("anti-ban", en.lower())

    def test_format_report_has_meaning_column_every_row(self):
        checks = [
            _check(id="network.mode", status="pass", explanation="Observed Mode='Rule'."),
            _check(id="privacy.telemetry", status="unknown", confidence="unknown",
                   explanation="[not_configured] DISABLE_TELEMETRY was not verified."),
            _check(id="consistency.unknown_future", status="pass", explanation="ok"),
        ]
        md_zh = format_report(checks, lang="zh")
        md_en = format_report(checks, lang="en")
        self.assertIn("| 检查项 | 状态 | 说明 | 详情 | 分组 | 建议 |", md_zh)
        self.assertIn("| check | status | meaning | detail | group | recommendation |", md_en)
        # each check's plain meaning appears
        self.assertIn(plain_check("network.mode", "zh"), md_zh)
        self.assertIn(plain_check("privacy.telemetry", "zh"), md_zh)
        self.assertIn(plain_check("consistency.unknown_future", "zh"), md_zh)
        self.assertIn(plain_check("network.mode", "en"), md_en)

    def test_footer_recommend_only_zh_en(self):
        md_zh = format_report([_check(id="network.mode", status="pass")], lang="zh")
        md_en = format_report([_check(id="network.mode", status="pass")], lang="en")
        self.assertIn("## 本工具不会自动做的事", md_zh)
        self.assertIn("改指纹", md_zh)
        self.assertIn("时区跟随节点", md_zh)
        self.assertIn("清环境洗白", md_zh)
        self.assertIn("防封评分伪装", md_zh)
        self.assertIn("DNS", md_zh)
        self.assertIn("TUN", md_zh)
        self.assertIn("只给建议", md_zh)

        self.assertIn("## What this tool does not do automatically", md_en)
        self.assertIn("fingerprint", md_en.lower())
        self.assertIn("timezone", md_en.lower())
        self.assertIn("anti-ban", md_en.lower())
        self.assertIn("DNS", md_en)
        self.assertIn("only recommends", md_en.lower())

    def test_score_named_consistency_not_ban(self):
        s = score_checks([_check(id="network.mode", status="pass")])
        self.assertEqual(s["score"], 100)
        self.assertEqual(s.get("score_kind"), "configuration_self_consistency")
        self.assertIn("consistent", s["label_en"].lower())
        self.assertIn("自洽", s["label_zh"])

        md_zh = format_report([_check(id="network.mode", status="pass")], lang="zh")
        md_en = format_report([_check(id="network.mode", status="pass")], lang="en")
        self.assertIn("## 配置自洽分", md_zh)
        self.assertIn("| 配置自洽分 |", md_zh)
        self.assertIn("不是**防封分", md_zh.replace(" ", ""))
        self.assertNotIn("## 防封", md_zh)
        self.assertNotIn("anti-ban score |", md_en.lower())
        self.assertIn("## Consistency score", md_en)
        self.assertIn("consistency score", md_en.lower())
        self.assertIn("configuration self-consistency", md_en.lower())
        self.assertIn("not** an anti-ban", md_en.lower())


if __name__ == "__main__":
    unittest.main()
