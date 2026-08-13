"""Integration tests for the local panel server (claude_shield.serve).

Starts a real ThreadingHTTPServer on a random high port bound to
127.0.0.1, then exercises the routes over HTTP.
"""

import http.client
import json
import socket
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import claude_shield.serve as serve_mod  # noqa: E402
from claude_shield import __version__  # noqa: E402


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture(scope="module")
def panel():
    port = _free_port()
    httpd = serve_mod.create_server(port)
    assert httpd.server_address[0] == "127.0.0.1", "panel must bind loopback only"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield {"base": f"http://127.0.0.1:{port}", "port": port, "httpd": httpd}
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=10)


def _get(url: str, timeout: float = 60.0):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.status, dict(resp.headers), resp.read()


def _raw(port: int, method: str, path: str, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request(method, path, headers=headers or {})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), body


class TestStaticPanel:
    def test_panel_html(self, panel):
        status, headers, body = _get(panel["base"] + "/")
        assert status == 200
        assert "text/html" in headers.get("Content-Type", "")
        html = body.decode("utf-8")
        for dom_id in (
            "readonly-banner",
            "btn-audit",
            "toggle-online",
            "btn-badge",
            "score-value",
            "grade-chip",
            "summary-chips",
            "report-md",
            "webrtc-list",
            "tz-info",
            "status-line",
            "error-box",
        ):
            assert f'id="{dom_id}"' in html, f"panel.html missing #{dom_id}"
        # 零外部资源: 静态页里不允许出现任何外部 URL / CDN 引用
        assert "http://" not in html and "https://" not in html
        assert "<script src" not in html and "<link rel" not in html

    def test_panel_security_headers(self, panel):
        status, headers, _ = _get(panel["base"] + "/")
        assert status == 200
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("Cache-Control") == "no-store"
        assert "default-src 'none'" in headers.get("Content-Security-Policy", "")

    def test_head_panel(self, panel):
        status, headers, _ = _raw(panel["port"], "HEAD", "/", {"Host": "127.0.0.1"})
        assert status == 200
        assert "text/html" in headers.get("Content-Type", "")

    def test_favicon_404(self, panel):
        status, _, _ = _raw(panel["port"], "GET", "/favicon.ico", {"Host": "127.0.0.1"})
        assert status == 404


class TestStatusApi:
    def test_status_json(self, panel):
        status, headers, body = _get(panel["base"] + "/api/status")
        assert status == 200
        assert "application/json" in headers.get("Content-Type", "")
        data = json.loads(body.decode("utf-8"))
        assert data["ok"] is True
        assert data["version"] == __version__
        assert data["host"] == "127.0.0.1"
        assert data["port"] == panel["port"]
        assert isinstance(data["time"], str)
        assert "cached" in data and "cached_at" in data and "cached_score" in data


class TestSecurity:
    def test_path_traversal_404(self, panel):
        for path in (
            "/../analyze.py",
            "/..%2Fclaude_shield%2F__main__.py",
            "/static/../claude_shield/__main__.py",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/api/../api/status",
            "/api/report/../../x",
        ):
            status, _, _ = _raw(panel["port"], "GET", path, {"Host": "127.0.0.1"})
            assert status == 404, f"expected 404 for {path}, got {status}"

    def test_non_loopback_host_header_403(self, panel):
        status, _, body = _raw(panel["port"], "GET", "/api/status", {"Host": "evil.example.com"})
        assert status == 403
        assert json.loads(body.decode("utf-8"))["ok"] is False

    def test_post_method_not_allowed(self, panel):
        status, _, _ = _raw(panel["port"], "POST", "/api/status", {"Host": "127.0.0.1"})
        assert status == 405


class TestBuildReportPayload:
    def test_redacts_sensitive_values(self):
        from claude_shield.models import AuditCheck

        checks = [
            AuditCheck(
                id="network.egress.test",
                title="t",
                category="network",
                status="pass",
                severity="info",
                confidence="high",
                explanation="egress via 192.168.1.5",
                recommendation="",
            )
        ]
        result = {
            "checks": checks,
            "summary": {"info": 1},
            "report_dict": {
                "tool_version": "1.4.2",
                "generated_at": "2026-01-01T00:00:00Z",
                "platform": {"os": "Windows", "version": "10", "hostname": "my-machine"},
            },
            "report_markdown": "leak 10.0.0.8 and user@example.com",
        }
        payload = serve_mod.build_report_payload(result, online=False)
        text = json.dumps(payload, ensure_ascii=False)
        assert "192.168.1.5" not in text
        assert "10.0.0.8" not in text
        assert "user@example.com" not in text
        assert "my-machine" not in text
        assert payload["ok"] is True
        assert payload["score"]["max_score"] == 100
        assert "must_fix" in payload["groups"]

    def test_empty_result_safe(self):
        payload = serve_mod.build_report_payload({}, online=False)
        assert payload["ok"] is True
        assert payload["summary"] == {}
        assert payload["report_markdown"] is None


class TestReportApi:
    def test_report_local_offline(self, panel):
        # Full local audit runs the real collector: allow generous time.
        status, headers, body = _get(panel["base"] + "/api/report?online=0", timeout=120)
        assert status == 200
        assert "application/json" in headers.get("Content-Type", "")
        data = json.loads(body.decode("utf-8"))
        assert data["ok"] is True
        assert data["online"] is False
        assert isinstance(data["version"], str) and data["version"]
        assert data["score"]["max_score"] == 100
        assert isinstance(data["score"]["score"], int) and 0 <= data["score"]["score"] <= 100
        assert data["score"]["grade"] in ("A", "B", "C", "D")
        for group in ("must_fix", "optional_consistency", "leave_alone"):
            assert isinstance(data["groups"][group], list)
        for severity in ("critical", "high", "medium", "low", "info"):
            assert severity in data["summary"]
        assert isinstance(data["report_markdown"], str) and len(data["report_markdown"]) > 50
        assert isinstance(data["generated_at"], str)
        assert isinstance(data["platform"], dict)


class TestBadgeApi:
    def test_badge_uses_cached_audit(self, panel, tmp_path, monkeypatch):
        # /api/badge should use the audit cached by the previous test and be fast.
        fake_path = tmp_path / "shield-badge.json"
        monkeypatch.setattr(serve_mod, "default_badge_path", lambda: fake_path)
        import time

        start = time.monotonic()
        status, headers, body = _get(panel["base"] + "/api/badge", timeout=60)
        elapsed = time.monotonic() - start
        assert status == 200
        assert "application/json" in headers.get("Content-Type", "")
        data = json.loads(body.decode("utf-8"))
        assert data["ok"] is True
        assert data["badge"]["schemaVersion"] == 1
        assert data["badge"]["label"] == "配置自洽分"
        assert data["badge"]["message"].endswith("/100")
        assert data["badge"]["color"] in ("brightgreen", "yellow", "red")
        assert data["saved_path"] == str(fake_path)
        assert data["shields_url"].startswith("https://img.shields.io/badge/dynamic/json?")
        assert data["markdown"].startswith("[![claude-shield](")
        assert fake_path.exists()
        assert elapsed < 30, "badge should reuse the cached audit (fast path)"
