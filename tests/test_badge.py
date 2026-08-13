"""Tests for claude_shield.badge (shield-badge.json + shields.io URL)."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from claude_shield.badge import (  # noqa: E402
    badge_color,
    default_badge_path,
    default_shield_json_url,
    make_badge,
    make_badge_from_result,
    make_badge_markdown,
    make_badge_md_link,
    score_from_result,
)


class TestBadgeColor:
    def test_green_band(self):
        assert badge_color(100) == "brightgreen"
        assert badge_color(90) == "brightgreen"
        assert badge_color(95.4) == "brightgreen"

    def test_yellow_band(self):
        assert badge_color(89) == "yellow"
        assert badge_color(75) == "yellow"
        assert badge_color(60) == "yellow"

    def test_red_band(self):
        assert badge_color(59) == "red"
        assert badge_color(0) == "red"

    def test_string_score_coerced(self):
        assert badge_color("88") == "yellow"


class TestMakeBadge:
    def test_payload_structure_and_file(self, tmp_path):
        out = tmp_path / "shield-badge.json"
        payload = make_badge(88, out)
        assert payload == {"schemaVersion": 1, "label": "配置自洽分", "message": "88/100", "color": "yellow"}
        assert "logoSvg" not in payload
        on_disk = json.loads(out.read_text(encoding="utf-8"))
        assert on_disk == payload

    def test_creates_parent_dirs(self, tmp_path):
        out = tmp_path / "a" / "b" / "shield-badge.json"
        make_badge(42, out)
        assert out.exists()

    def test_low_score_color_in_file(self, tmp_path):
        out = tmp_path / "shield-badge.json"
        make_badge(12, out)
        assert json.loads(out.read_text(encoding="utf-8"))["color"] == "red"


class TestScoreFromResult:
    def _real_checks(self):
        from claude_shield.analyze import analyze_snapshot

        return analyze_snapshot({"System": {"ComputerName": "test-host"}})

    def test_score_from_result_with_checks(self):
        result = {"checks": self._real_checks()}
        score = score_from_result(result)
        assert isinstance(score, int)
        assert 0 <= score <= 100

    def test_score_from_result_empty(self):
        assert score_from_result({}) is None
        assert score_from_result({"checks": []}) is None

    def test_make_badge_from_result(self, tmp_path):
        result = {"checks": self._real_checks()}
        out = tmp_path / "shield-badge.json"
        payload = make_badge_from_result(result, out)
        assert out.exists()
        assert payload["message"].endswith("/100")

    def test_make_badge_from_result_no_checks_raises(self, tmp_path):
        with pytest.raises(ValueError):
            make_badge_from_result({"checks": []}, tmp_path / "badge.json")


class TestBadgeUrl:
    def test_markdown_url_shape(self):
        raw = "https://example.com/user/repo/raw/main/shield-badge.json"
        url = make_badge_markdown(shield_json_url=raw)
        assert url.startswith("https://img.shields.io/badge/dynamic/json?url=")
        assert "query=$.message" in url
        assert "label=" in url
        assert "example.com" in url  # URL-encoded inside the url= param

    def test_default_json_url_from_metadata(self):
        url = default_shield_json_url()
        assert url.startswith("https://github.com/")
        assert url.endswith("/raw/main/shield-badge.json")

    def test_md_link_wraps_url(self):
        raw = "https://example.com/user/repo/raw/main/shield-badge.json"
        link = make_badge_md_link(shield_json_url=raw)
        assert link.startswith("[![claude-shield](https://img.shields.io/badge/dynamic/json?")
        assert "(https://img.shields.io" in link

    def test_default_badge_path_in_project_root(self):
        path = default_badge_path()
        assert path.name == "shield-badge.json"
        assert (path.parent / "pyproject.toml").exists() or (path.parent / "static" / "panel.html").exists()
