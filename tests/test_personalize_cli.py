"""Personalization: CLI-agent TUN/global guidance + terminology mapping."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_shield.personalize import (
    build_personal_guidance,
    detect_cli_agent,
    format_personal_section,
)


def _snapshot(claude=True, procs=None):
    data = {"System": {"MihomoProcessRunning": True}}
    if claude:
        data["ClaudeCode"] = {"DisableTelemetryVars": [{"Name": "DISABLE_TELEMETRY", "Present": True}]}
    if procs:
        data["System"]["PrimaryProxyProcesses"] = procs
    return data


class TestCliAgentDetection(unittest.TestCase):
    def test_claude_code_section_detected(self):
        self.assertTrue(detect_cli_agent(_snapshot(claude=True)))

    def test_empty_snapshot_not_detected(self):
        self.assertFalse(detect_cli_agent({"System": {}}))

    def test_cli_process_detected(self):
        snap = _snapshot(claude=False, procs=[{"Name": "codex", "Label": "Codex", "Running": True}])
        self.assertTrue(detect_cli_agent(snap))


class TestCliTunGuidance(unittest.TestCase):
    def test_cli_agent_adds_tun_action(self):
        g = build_personal_guidance(
            _snapshot(claude=True),
            [],
            intended_mode="system_proxy",
            lang="zh",
            cli_agent=True,
        )
        titles = [a["title"] for a in g["actions"]]
        self.assertTrue(any("CLI" in t for t in titles), titles)
        md = format_personal_section(g, "zh")
        self.assertIn("虚拟网卡(TUN)", md)
        self.assertIn("检测到 CLI 端 Agent", md)

    def test_cli_terminology_names_other_clients(self):
        # v2rayN label: terminology line mentions TUN 模式
        g = build_personal_guidance(
            _snapshot(claude=True, procs=[{"Name": "v2rayN", "Label": "v2rayN", "Running": True}]),
            [],
            lang="zh",
            cli_agent=True,
        )
        md = format_personal_section(g, "zh")
        self.assertIn("v2rayN", md)

    def test_system_proxy_no_cli_keeps_plain_tun_action(self):
        from claude_shield.models import AuditCheck

        tun_pass = AuditCheck(
            id="network.tun",
            title="TUN enabled",
            category="network",
            status="pass",
            severity="info",
            confidence="high",
            explanation="TunEnabled=False. Matches system_proxy.",
        )
        g = build_personal_guidance(
            {"System": {}},
            [tun_pass],
            intended_mode="system_proxy",
            lang="zh",
            cli_agent=False,
        )
        titles = [a["title"] for a in g["actions"]]
        self.assertTrue(any("保持 TUN 关闭" in t for t in titles), titles)


if __name__ == "__main__":
    unittest.main()
