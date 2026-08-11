"""Audit check list diff helpers."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_shield.diff import (
    diff_audits,
    format_diff_markdown,
    load_checks_from_report_dict,
)
from claude_shield.models import AuditCheck


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


class TestDiffAudits(unittest.TestCase):
    def test_status_changed(self):
        before = [
            _check(id="network.tun", title="TUN", status="unknown"),
            _check(id="network.mode", title="Mode", status="pass"),
        ]
        after = [
            _check(id="network.tun", title="TUN", status="pass"),
            _check(id="network.mode", title="Mode", status="pass"),
        ]
        d = diff_audits(before, after)
        self.assertEqual(len(d["status_changed"]), 1)
        row = d["status_changed"][0]
        self.assertEqual(row["id"], "network.tun")
        self.assertEqual(row["before"], "unknown")
        self.assertEqual(row["after"], "pass")
        self.assertEqual(row["title"], "TUN")
        self.assertEqual(d["added"], [])
        self.assertEqual(d["removed"], [])
        self.assertEqual(d["unchanged"], 1)

    def test_added_and_removed(self):
        before = [
            _check(id="a.old", title="Old", status="pass"),
            _check(id="shared", title="Shared", status="warning"),
        ]
        after = [
            _check(id="b.new", title="New", status="fail"),
            _check(id="shared", title="Shared", status="warning"),
        ]
        d = diff_audits(before, after)
        self.assertEqual([x["id"] for x in d["added"]], ["b.new"])
        self.assertEqual([x["id"] for x in d["removed"]], ["a.old"])
        self.assertEqual(d["status_changed"], [])
        self.assertEqual(d["unchanged"], 1)

    def test_dict_rows(self):
        before = [{"id": "x", "status": "fail", "title": "X"}]
        after = [{"id": "x", "status": "pass", "title": "X"}]
        d = diff_audits(before, after)
        self.assertEqual(d["status_changed"][0]["before"], "fail")
        self.assertEqual(d["status_changed"][0]["after"], "pass")

    def test_format_diff_markdown_zh(self):
        d = diff_audits(
            [_check(id="network.dns", title="DNS", status="warning")],
            [_check(id="network.dns", title="DNS", status="pass")],
        )
        md = format_diff_markdown(d, lang="zh")
        self.assertIn("# 审计对比", md)
        self.assertIn("## 状态变化", md)
        self.assertIn("network.dns", md)
        self.assertIn("warning", md)
        self.assertIn("pass", md)
        self.assertIn("## 新增", md)
        self.assertIn("## 移除", md)

    def test_format_diff_markdown_en(self):
        d = {
            "added": [{"id": "n", "status": "pass", "title": "N"}],
            "removed": [],
            "status_changed": [],
            "unchanged": 0,
        }
        md = format_diff_markdown(d, lang="en")
        self.assertIn("# Audit diff", md)
        self.assertIn("## Added", md)
        self.assertIn("| n |", md)

    def test_load_checks_from_report_dict(self):
        report = {
            "schema_version": "1.0",
            "checks": [
                {"id": "network.mode", "status": "pass", "title": "Mode"},
                {"id": "network.tun", "status": "unknown", "title": "TUN"},
            ],
        }
        checks = load_checks_from_report_dict(report)
        self.assertEqual(len(checks), 2)
        self.assertEqual(checks[0]["id"], "network.mode")

        nested = {"report_dict": report}
        self.assertEqual(len(load_checks_from_report_dict(nested)), 2)

        bare = load_checks_from_report_dict(report["checks"])
        self.assertEqual(len(bare), 2)

        self.assertEqual(load_checks_from_report_dict(None), [])
        self.assertEqual(load_checks_from_report_dict({}), [])

    def test_diff_from_report_dicts(self):
        before_rd = {
            "checks": [
                {"id": "network.allow_lan", "status": "warning", "title": "LAN"},
            ]
        }
        after_rd = {
            "checks": [
                {"id": "network.allow_lan", "status": "pass", "title": "LAN"},
            ]
        }
        d = diff_audits(
            load_checks_from_report_dict(before_rd),
            load_checks_from_report_dict(after_rd),
        )
        self.assertEqual(d["status_changed"][0]["id"], "network.allow_lan")
        self.assertEqual(d["status_changed"][0]["before"], "warning")
        self.assertEqual(d["status_changed"][0]["after"], "pass")


if __name__ == "__main__":
    unittest.main()
