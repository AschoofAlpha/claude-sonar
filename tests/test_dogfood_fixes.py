"""Dogfood-driven report/probe fixes: infer mode, bilingual locale, display."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_sonar.analyze import analyze_snapshot
from claude_sonar.analysis.system import infer_intended_mode
from claude_sonar.models import AuditCheck
from claude_sonar.personalize import build_personal_guidance
from claude_sonar.probes.cross_site import check_cross_site_routing
from claude_sonar.report import classify_action, format_report, score_checks


def _ids(checks):
    return {c.id: c for c in checks}


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


def _mihomo(tun_enabled):
    return {
        "AppConfigPresent": True,
        "RuntimeConfigPresent": True,
        "Mode": "Rule",
        "AllowLan": False,
        "TunEnabled": tun_enabled,
        "StrictRoute": True,
        "DnsEnabled": True,
        "DnsMode": "fake-ip",
        "DnsHijackAny53": True,
    }


class TestInferIntendedMode(unittest.TestCase):
    def test_infer_system_proxy_from_loopback_and_tun_off(self):
        snap = {
            "Mihomo": _mihomo(False),
            "System": {"SystemProxy": {"Enabled": True, "PointsToLoopback": True}},
        }
        self.assertEqual(infer_intended_mode(snap), "system_proxy")

    def test_infer_full_tunnel_when_tun_on(self):
        snap = {"Mihomo": _mihomo(True), "System": {}}
        self.assertEqual(infer_intended_mode(snap), "full_tunnel")

    def test_infer_none_without_system_proxy(self):
        self.assertIsNone(infer_intended_mode({"Mihomo": _mihomo(False)}))

    def test_analyze_infers_system_proxy_tun_off_pass(self):
        checks = analyze_snapshot({
            "Mihomo": _mihomo(False),
            "System": {"SystemProxy": {"Enabled": True, "PointsToLoopback": True}},
        })
        tun = _ids(checks)["network.tun"]
        self.assertEqual(tun.status, "pass")
        self.assertIn("system_proxy", tun.explanation)

    def test_explicit_mode_wins_over_infer(self):
        checks = analyze_snapshot(
            {
                "Mihomo": _mihomo(False),
                "System": {"SystemProxy": {"Enabled": True, "PointsToLoopback": True}},
            },
            intended_mode="full_tunnel",
        )
        self.assertEqual(_ids(checks)["network.tun"].status, "warning")


class TestBilingualLocale(unittest.TestCase):
    def test_en_plus_zh_hans_is_pass(self):
        checks = analyze_snapshot({
            "System": {
                "Culture": "en-US",
                "UICulture": "zh-Hans-SG",
                "SystemLocale": "en-US",
                "UserLanguageList": ["en-US", "zh-Hans-SG"],
            }
        })
        loc = _ids(checks)["system.locale"]
        self.assertEqual(loc.status, "pass")

    def test_en_plus_ja_still_warns(self):
        checks = analyze_snapshot({
            "System": {
                "Culture": "en-US",
                "UICulture": "ja-JP",
                "SystemLocale": "en-US",
            }
        })
        self.assertEqual(_ids(checks)["system.locale"].status, "warning")


class TestPresenceArtifactsLeaveAlone(unittest.TestCase):
    def test_local_claude_dir_does_not_score(self):
        check = _check(
            id="privacy.local_device_id",
            status="unknown",
            confidence="unknown",
            explanation="存在本机 Claude 相关路径（只看有无；不读取 ID）。",
        )
        self.assertEqual(classify_action(check), "leave_alone")
        scored = score_checks([check])
        self.assertEqual(scored["breakdown"]["optional_penalty"], 0)

    def test_telemetry_cache_does_not_score(self):
        check = _check(
            id="privacy.telemetry_cache",
            status="unknown",
            confidence="unknown",
            explanation="Claude 主目录下存在遥测/缓存相关路径。",
        )
        self.assertEqual(classify_action(check), "leave_alone")


class TestDefaultReportOmitsAllResults(unittest.TestCase):
    def test_default_has_three_groups_not_all_results(self):
        md = format_report([
            _check(id="network.mode", status="pass", explanation="Observed Mode='Rule'."),
        ], lang="zh")
        self.assertIn("## 必须处理", md)
        self.assertIn("## 可选一致性", md)
        self.assertIn("## 保持不动", md)
        self.assertNotIn("## 全部结果", md)

    def test_include_all_results_opt_in(self):
        md = format_report([
            _check(id="network.mode", status="pass", explanation="Observed Mode='Rule'."),
        ], lang="zh", include_all_results=True)
        self.assertIn("## 全部结果", md)

    def test_zh_report_has_no_english_sentences(self):
        md = format_report([
            _check(
                id="network.cross_site.routing",
                status="unknown",
                confidence="unknown",
                explanation="Fewer than two sites returned a usable egress token.",
            ),
            _check(
                id="network.proxy_autoconfig",
                status="pass",
                explanation="No PAC URL; registry AutoDetect missing (typically off).",
            ),
        ], lang="zh")
        self.assertNotIn("Fewer than two", md)
        self.assertNotIn("No PAC URL", md)
        self.assertNotIn("Treat as incomplete", md)

    def test_supplemental_privacy_collapsed_in_default(self):
        checks = [
            _check(
                id=cid,
                status="unknown",
                confidence="unknown",
                explanation="[folded_optional] 补充项未配置，默认可忽略.",
            )
            for cid in (
                "privacy.prompt_history",
                "privacy.subprocess_scrub",
                "privacy.otel_user_prompts",
                "privacy.otel_tool_content",
                "privacy.otel_tool_details",
                "privacy.otel_raw_api",
            )
        ]
        md = format_report(checks, lang="zh")
        self.assertEqual(md.count("privacy.otel_user_prompts"), 0)
        self.assertIn("补充隐私", md)


class TestCrossSiteReuse(unittest.TestCase):
    def test_reuses_provided_observations_without_fetch(self):
        check = check_cross_site_routing(
            observations=[
                {"site": "www.cloudflare.com", "observed_address": "<CRED:aaaaaa>", "address_family": "ipv4"},
                {"site": "api.ipify.org", "observed_address": "<CRED:aaaaaa>", "address_family": "ipv4"},
            ]
        )
        self.assertEqual(check.status, "pass")
        self.assertIn("一致", check.explanation)

    def test_shared_redactor_makes_endpoint_tokens_comparable(self):
        from claude_sonar.probes import egress as egress_probes
        from claude_sonar.probes.base import ProbeContext, ProbeEndpoint
        from claude_sonar.redaction import Redactor

        ep = ProbeEndpoint(
            id="t1",
            purpose="test",
            url="https://example.com",
            enabled=True,
            supports_ipv4=True,
            supports_ipv6=True,
            expected_content_type="text/plain",
            maximum_response_bytes=16384,
        )
        ctx = ProbeContext(timeout=2, endpoint=ep)
        shared = Redactor()
        results = []
        with mock.patch.object(
            egress_probes, "run_python_probe", return_value=("ip=203.0.113.50\n", "direct_pinned")
        ), mock.patch.object(
            egress_probes, "run_curl_probe", return_value=("ip=203.0.113.50\n", "direct_pinned")
        ):
            for cid in ("a", "b"):
                ctx.endpoint.id = cid
                results.append(egress_probes.check_egress_consistency(ctx, redactor=shared))
        toks = [
            item.data["observed_address"]
            for res in results
            for item in (res.evidence or [])
            if item.type == "runtime_egress"
        ]
        self.assertEqual(len(set(toks)), 1, toks)


class TestPersonalizeEnvProxy(unittest.TestCase):
    def test_env_proxy_pass_skips_cli_tun_push(self):
        env = _check(
            id="network.env_proxy",
            status="pass",
            explanation="检测到代理环境变量：HTTPS_PROXY, HTTP_PROXY, NO_PROXY.",
        )
        g = build_personal_guidance(
            {"ClaudeCode": {"DisableTelemetryVars": [{"Present": True}]}},
            [env],
            intended_mode="system_proxy",
            lang="zh",
            cli_agent=True,
        )
        titles = [a["title"] for a in g["actions"]]
        self.assertFalse(any("开全局" in t and "TUN" in t for t in titles), titles)


class TestDnsHijackSkipDoh(unittest.TestCase):
    def test_skip_doh_when_fakeip_and_hijack_pass(self):
        from claude_sonar.probes.dns_egress_probe import check_dns_egress_consistency

        check = check_dns_egress_consistency(
            timeout=1,
            existing_checks=[
                _check(id="network.dns_mode", status="pass", explanation="DnsMode='fake-ip'."),
                _check(id="network.dns_hijack", status="pass", explanation="DnsHijackAny53=True."),
            ],
        )
        self.assertEqual(check.status, "pass")
        self.assertIn("fake-IP", check.explanation)


if __name__ == "__main__":
    unittest.main()
