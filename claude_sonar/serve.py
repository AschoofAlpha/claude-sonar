"""Zero-dependency local panel server for Claude Sonar.

Serves the single-file panel (``static/panel.html``) plus a read-only JSON
API on ``127.0.0.1`` only. Every report payload passes through ``Redactor``
before it leaves the process. Online probing stays off unless the panel
explicitly requests ``online=1``.

Usage::

    from claude_sonar.serve import serve
    serve(port=8765, open_browser=True)   # blocks until Ctrl+C
"""

from __future__ import annotations

import json
import sys
import threading
import time
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from .__version__ import __version__
from .analyze import CollectorError, run_full_audit
from .badge import default_badge_path, make_badge_from_result, make_badge_markdown
from .models import to_dict
from .redaction import Redactor
from .report import group_checks, score_checks

HOST = "127.0.0.1"
DEFAULT_PORT = 8765

# Resolved lazily so ``import claude_sonar.serve`` never fails when the
# bundled panel file is absent (e.g. source checkout without static/).
_PANEL_PATH = None


def panel_path():
    """Resolve static/panel.html without depending on .resources (which may
    be shadowed by a data-only ``claude_sonar/resources`` package)."""
    global _PANEL_PATH
    if _PANEL_PATH is None:
        import sysconfig

        candidates = [
            Path(__file__).resolve().parent.parent / "static" / "panel.html",  # source checkout
            Path(__file__).resolve().parent / "static" / "panel.html",  # static/ inside the package
            Path(sysconfig.get_path("data")) / "share" / "claude-sonar" / "static" / "panel.html",
        ]
        _PANEL_PATH = next((p for p in candidates if p.exists()), candidates[0])
    return _PANEL_PATH

_CSP = (
    "default-src 'none'; "
    "script-src 'unsafe-inline'; "
    "style-src 'unsafe-inline'; "
    "img-src data:; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'none'"
)

# In-memory cache for the last audit (payload + raw result + timestamp).
_cache_lock = threading.Lock()
_audit_lock = threading.Lock()
_cache: Dict[str, Any] = {"payload": None, "result": None, "at": None}


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_report_payload(result: Dict[str, Any], online: bool) -> Dict[str, Any]:
    """Turn a ``run_full_audit`` result into a redacted, JSON-safe payload.

    Group items are sorted by status (fail → pass → warning → unknown) and
    each check carries Chinese labels (``title_zh`` / ``explanation_zh`` /
    ``recommendation_zh``) for the panel UI.
    """
    from .report import plain_check, sort_checks, translate_detail, translate_recommendation

    checks = result.get("checks") or []
    report_dict = result.get("report_dict") or {}

    def _zh_enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        cid = str(item.get("id") or "")
        item["title_zh"] = plain_check(cid, "zh")
        item["explanation_zh"] = (
            translate_detail(str(item.get("explanation") or ""), "zh")
            or item.get("explanation")
        )
        item["recommendation_zh"] = (
            translate_recommendation(str(item.get("recommendation") or ""), "zh")
            or item.get("recommendation")
        )
        return item

    try:
        scored = score_checks(checks)
    except Exception:
        scored = {
            "score": None,
            "max_score": 100,
            "grade": None,
            "label_zh": None,
            "label_en": None,
            "score_kind": "configuration_self_consistency",
            "breakdown": {},
        }
    try:
        grouped = group_checks(checks)
        groups_json = {
            key: [_zh_enrich(to_dict(c)) for c in sort_checks(items)]
            for key, items in grouped.items()
        }
    except Exception:
        groups_json = {}

    # ---- Egress overview: extract from existing checks for the panel cards ----
    egress_summary: Dict[str, Any] = {"available": False}
    try:
        check_map = {str(c.get("id") or ""): c for c in (to_dict(ch) for ch in checks)}
        ip_rep = check_map.get("network.ip_reputation")
        cf_trace = check_map.get("network.egress.runtime_consistency.cloudflare-trace")
        dns_egress = check_map.get("network.dns.egress_consistency")
        dns_consistency = check_map.get("network.dns.consistency")
        tls_fp = check_map.get("network.tls.fingerprint")
        baseurl = check_map.get("network.anthropic_baseurl")

        def _explanation_zh(c: Dict[str, Any]) -> str:
            return str(
                translate_detail(str(c.get("explanation") or ""), "zh")
                or c.get("explanation") or ""
            )

        eg_ip = eg_country = eg_asn = eg_org = ""
        if ip_rep:
            ex = str(ip_rep.get("explanation") or "")
            for frag in ex.split("."):
                frag_lower = frag.strip().lower()
                if frag_lower.startswith("country code:"):
                    eg_country = frag_lower.replace("country code:", "").strip().upper()
                if frag_lower.startswith("asn:"):
                    eg_asn = frag_lower.replace("asn:", "").strip()
                if frag_lower.startswith("org/provider"):
                    val = frag_lower.split("label present", 1)[0].replace("org/provider", "").strip()
                    if val:
                        eg_org = val
            eg_ip = "（已脱敏）"

        dns_status = "unknown"
        if dns_egress:
            dns_status = str(dns_egress.get("status") or "unknown")

        dns_consist_status = "unknown"
        if dns_consistency:
            dns_consist_status = str(dns_consistency.get("status") or "unknown")

        tls_status = "unknown"
        tls_fp_val = ""
        if tls_fp:
            tls_status = str(tls_fp.get("status") or "unknown")
            ex_tls = _explanation_zh(tls_fp)
            if "JA4=" in ex_tls:
                import re as _re
                m = _re.search(r"JA4=([a-z0-9_]+)", ex_tls)
                if m:
                    tls_fp_val = m.group(1)

        baseurl_status = "unknown"
        if baseurl:
            baseurl_status = str(baseurl.get("status") or "unknown")

        cf_status = cf_trace.get("status") if cf_trace else "unknown"

        egress_summary = {
            "available": True,
            "online": bool(online),
            "egress_ip": eg_ip,
            "egress_country": eg_country,
            "egress_asn": eg_asn,
            "egress_org": eg_org,
            "egress_status": str(cf_status or "unknown"),
            "dns_egress_status": dns_status,
            "dns_consistency_status": dns_consist_status,
            "tls_status": tls_status,
            "tls_fingerprint": tls_fp_val,
            "baseurl_status": baseurl_status,
        }
    except Exception:
        pass

    payload: Dict[str, Any] = {
        "ok": True,
        "online": bool(online),
        "version": report_dict.get("tool_version") or __version__,
        "generated_at": report_dict.get("generated_at") or _utcnow(),
        "platform": report_dict.get("platform") or {},
        "summary": result.get("summary") or report_dict.get("summary") or {},
        "score": scored,
        "groups": groups_json,
        "egress_summary": egress_summary,
        "report_markdown": result.get("report_markdown"),
    }
    # Belt and suspenders: redact the assembled payload once more before it
    # leaves the process (run_full_audit already redacts its own outputs).
    redacted = Redactor().scan_and_redact(payload)
    return json.loads(json.dumps(redacted, ensure_ascii=False, default=str))


def _run_audit(online: bool, timeout: float) -> Dict[str, Any]:
    if online:
        timeout = max(1.0, min(float(timeout), 30.0))
    return run_full_audit(probe_timeout=timeout, online=online)


class PanelRequestHandler(BaseHTTPRequestHandler):
    """Read-only handler: panel HTML, status, redacted report, badge JSON."""

    server_version = "ClaudeShieldPanel/1.0"
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet, concise
        print(f"[panel] {self.address_string()} {fmt % args}", file=sys.stderr)

    def handle_one_request(self) -> None:
        # A client that aborts mid-request (curl pipe closed, tab closed) is
        # not a server error; swallow the reset quietly.
        try:
            super().handle_one_request()
        except (ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True

    def _send(self, code: int, body: str, content_type: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", _CSP)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str)
        self._send(code, body, "application/json; charset=utf-8")

    def _host_ok(self) -> bool:
        # Anti-DNS-rebinding: only loopback Host headers are accepted.
        host = (self.headers.get("Host") or "").lower().strip()
        if not host:
            return False
        name = host.split(":", 1)[0]
        return name in ("127.0.0.1", "localhost", "[::1]")

    # -- routes -----------------------------------------------------------

    def do_HEAD(self) -> None:
        if self._host_ok() and urlparse(self.path).path == "/":
            try:
                data = panel_path().read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
            except FileNotFoundError:
                self._send(404, "panel.html not found", "text/plain; charset=utf-8")
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if not self._host_ok():
            self._json(403, {"ok": False, "error": "invalid Host header; panel is loopback-only"})
            return

        if path == "/":
            self._serve_panel()
        elif path == "/api/status":
            self._api_status()
        elif path == "/api/report":
            self._api_report(query)
        elif path == "/api/badge":
            self._api_badge()
        else:
            self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # read-only panel: no mutations via HTTP
        self._json(405, {"ok": False, "error": "method not allowed; panel is read-only"})

    # -- endpoints --------------------------------------------------------

    def _serve_panel(self) -> None:
        try:
            data = panel_path().read_bytes()
        except FileNotFoundError:
            self._send(404, "panel.html not found", "text/plain; charset=utf-8")
            return
        self._send(200, data.decode("utf-8"), "text/html; charset=utf-8")

    def _api_status(self) -> None:
        with _cache_lock:
            cached_payload = _cache["payload"]
            cached_at = _cache["at"]
        cached_score = None
        if cached_payload:
            score = cached_payload.get("score") or {}
            cached_score = {
                "score": score.get("score"),
                "grade": score.get("grade"),
                "label_zh": score.get("label_zh"),
            }
        self._json(200, {
            "ok": True,
            "version": __version__,
            "time": _utcnow(),
            "host": HOST,
            "port": self.server.server_address[1],
            "cached": bool(cached_payload),
            "cached_at": cached_at,
            "cached_score": cached_score,
        })

    def _api_report(self, query: Dict[str, Any]) -> None:
        # Online probes are ON by default in the panel (user preference:
        # panel = full picture, opt out via online=0).
        raw_online = (query.get("online") or ["1"])[0].strip().lower()
        online = raw_online not in ("0", "false", "no", "off")
        try:
            timeout = float((query.get("timeout") or ["5"])[0])
        except ValueError:
            timeout = 5.0

        with _audit_lock:
            try:
                result = _run_audit(online=online, timeout=timeout)
            except CollectorError as exc:
                self._json(500, {"ok": False, "error": str(exc), "online": online})
                return
            except Exception as exc:  # pragma: no cover - defensive
                message = Redactor().scan_and_redact(str(exc))
                self._json(500, {"ok": False, "error": message, "online": online})
                return
            payload = build_report_payload(result, online=online)
            with _cache_lock:
                _cache["payload"] = payload
                _cache["result"] = result
                _cache["at"] = _utcnow()
        self._json(200, payload)

    def _api_badge(self) -> None:
        with _audit_lock:
            with _cache_lock:
                result = _cache["result"]
            if result is None:
                try:
                    result = _run_audit(online=False, timeout=5.0)
                except CollectorError as exc:
                    self._json(500, {"ok": False, "error": str(exc)})
                    return
                except Exception as exc:  # pragma: no cover - defensive
                    self._json(500, {"ok": False, "error": Redactor().scan_and_redact(str(exc))})
                    return
                with _cache_lock:
                    _cache["result"] = result
            try:
                badge = make_badge_from_result(result, default_badge_path())
            except (ValueError, OSError) as exc:
                self._json(500, {"ok": False, "error": str(exc)})
                return
        shields_url = make_badge_markdown()
        self._json(200, {
            "ok": True,
            "badge": badge,
            "saved_path": str(default_badge_path()),
            "shields_url": shields_url,
            "markdown": f"[![claude-sonar]({shields_url})]({shields_url})",
        })


class PanelHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def create_server(port: int = DEFAULT_PORT) -> PanelHTTPServer:
    """Build (but do not start) the panel server, bound to 127.0.0.1."""
    return PanelHTTPServer((HOST, port), PanelRequestHandler)


def serve(
    port: int = DEFAULT_PORT,
    open_browser: bool = False,
    open_delay: float = 0.0,
) -> PanelHTTPServer:
    """Serve the read-only panel on 127.0.0.1 until interrupted.

    ``open_browser=True`` opens the panel in the default browser after the
    socket is bound. ``open_delay`` (seconds) waits before opening the
    browser so the user can read the chat tables first.
    """
    httpd = create_server(port)
    url = f"http://{HOST}:{httpd.server_address[1]}/"
    print(f"claude-sonar panel (read-only) -> {url}", flush=True)
    print("Bound to 127.0.0.1 only. Press Ctrl+C to stop.", flush=True)
    if open_browser:
        try:
            if open_delay and open_delay > 0:
                time.sleep(min(float(open_delay), 60.0))
            webbrowser.open(url)
        except Exception:  # pragma: no cover - browser launch is best-effort
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nclaude-sonar panel stopped.", flush=True)
    finally:
        httpd.server_close()
    return httpd


__all__ = ["serve", "create_server", "build_report_payload", "panel_path", "HOST", "DEFAULT_PORT"]
