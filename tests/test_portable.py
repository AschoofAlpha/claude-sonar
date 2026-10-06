"""Tests for the Windows portable launcher and frozen resource lookup."""

import sys
from pathlib import Path

import pytest

from claude_sonar import portable
from claude_sonar import resources
from claude_sonar import serve as serve_module


class _FakeServer:
    def __init__(self):
        self.closed = False

    def server_close(self):
        self.closed = True


def test_portable_no_args_starts_ephemeral_read_only_panel(monkeypatch):
    calls = {}

    def fake_serve(**kwargs):
        calls.update(kwargs)
        return _FakeServer()

    monkeypatch.setattr(portable, "serve", fake_serve)
    assert portable.main([]) == 0
    assert calls == {
        "port": 0,
        "open_browser": True,
        "open_delay": 0.0,
        "pre_audit": False,
        "online": True,
        "timeout": 5.0,
        "lang": "zh",
    }


def test_portable_cli_mode_forwards_arguments(monkeypatch):
    calls = {}

    def fake_cli(argv):
        calls["argv"] = argv
        return 7

    monkeypatch.setattr(portable, "cli_main", fake_cli)
    assert portable.main(["--json", "--timeout", "2"]) == 7
    assert calls["argv"] == ["--json", "--timeout", "2"]


def test_resource_path_reads_frozen_meipass(monkeypatch, tmp_path):
    target = tmp_path / "share" / "claude-sonar" / "scripts" / "probe.ps1"
    target.parent.mkdir(parents=True)
    target.write_text("Write-Output ok", encoding="utf-8")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert resources.resource_path("scripts", "probe.ps1") == target


def test_panel_path_reads_frozen_meipass(monkeypatch, tmp_path):
    target = tmp_path / "share" / "claude-sonar" / "static" / "panel.html"
    target.parent.mkdir(parents=True)
    target.write_text("<h1>panel</h1>", encoding="utf-8")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    monkeypatch.setattr(serve_module, "_PANEL_PATH", None)
    assert serve_module.panel_path() == target


def test_portable_writes_chinese_to_redirected_windows_streams(monkeypatch):
    import io

    output = io.BytesIO()
    error = io.BytesIO()
    stdout = io.TextIOWrapper(output, encoding="cp1252")
    stderr = io.TextIOWrapper(error, encoding="cp1252")

    def print_chinese(argv):
        print("检测报告", flush=True)
        print("检测提示", file=sys.stderr, flush=True)
        return 0

    monkeypatch.setattr(portable, "cli_main", print_chinese)
    with monkeypatch.context() as m:
        m.setattr(sys, "stdout", stdout)
        m.setattr(sys, "stderr", stderr)
        assert portable.main(["--json"]) == 0
    assert output.getvalue().decode("utf-8").strip() == "检测报告"
    assert error.getvalue().decode("utf-8").strip() == "检测提示"


def test_frozen_repo_scan_discovers_bundled_semgrep_rules(monkeypatch, tmp_path):
    from claude_sonar.reposcan import rules

    target = tmp_path / "claude_sonar" / "resources" / "semgrep_rules"
    target.mkdir(parents=True)
    (target / "python.yaml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    assert rules.rules_dir() == target
    assert rules.rule_files_for_languages({"python"}) == [target / "python.yaml"]


def test_build_manifest_covers_runtime_resources_at_expected_paths():
    from scripts import build_portable_windows as builder

    args = builder._data_args()
    bundled = set()
    for flag, value in zip(args[::2], args[1::2]):
        assert flag == "--add-data"
        source, destination = value.split(builder.os.pathsep, 1)
        source = Path(source)
        if source.is_dir():
            bundled.update(
                (Path(destination) / p.relative_to(source)).as_posix()
                for p in source.rglob("*") if p.is_file()
            )
        else:
            assert source.is_file()
            bundled.add((Path(destination) / source.name).as_posix())

    assert {
        "share/claude-sonar/static/panel.html",
        "share/claude-sonar/scripts/collect_windows_network.ps1",
        "claude_sonar/resources/known_baseurl_blacklist.txt",
        "claude_sonar/resources/known_baseurl_labwords.txt",
        "claude_sonar/resources/semgrep_rules/python.yaml",
        "claude_sonar/resources/semgrep_rules/NOTICE.md",
        "LICENSE",
    } <= bundled
    assert not any(
        name.endswith((".pyc", ".env", "upload_pypi.py"))
        or "/remediate_" in name
        for name in bundled
    )
