"""Explicit, bounded network speed observations for the local panel.

The panel never starts these probes automatically.  Every request targets a
fixed Cloudflare speed-test endpoint; callers cannot provide an arbitrary URL.
The payload is zero-filled and capped so the user can see the traffic cost
before choosing download or upload.
"""

from __future__ import annotations

import ssl
import time
import urllib.request
from statistics import median
from typing import Any, Dict, Optional
from urllib.parse import urlparse

_SPEED_HOST = "speed.cloudflare.com"
_LATENCY_URL = "https://speed.cloudflare.com/__down?bytes=1"
_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes={size}"
_UPLOAD_URL = "https://speed.cloudflare.com/__up"
_MAX_BYTES = 1024 * 1024
_DEFAULT_BYTES = 256 * 1024
_LATENCY_SAMPLES = 3


class SpeedTestError(RuntimeError):
    """Raised for a bounded speed-test transport failure."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise SpeedTestError("redirect blocked")


_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler(),
    _NoRedirect(),
    urllib.request.HTTPSHandler(context=ssl.create_default_context()),
)


def _size(value: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = _DEFAULT_BYTES
    return max(64 * 1024, min(parsed, _MAX_BYTES))


def _timeout(value: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = 5.0
    return max(1.0, min(parsed, 15.0))


def _request(method: str, url: str, *, body: Optional[bytes], timeout: float, max_bytes: int) -> bytes:
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != _SPEED_HOST
        or parsed.port is not None
    ):
        raise SpeedTestError("fixed endpoint validation failed")
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-store",
            "User-Agent": "claude-sonar-speed-observer",
            "Content-Type": "application/octet-stream" if body is not None else "*/*",
        },
    )
    try:
        with _OPENER.open(req, timeout=timeout) as response:
            data = response.read(max_bytes + 1)
    except Exception as exc:  # noqa: BLE001 - caller renders this as unknown
        raise SpeedTestError(type(exc).__name__) from exc
    if len(data) > max_bytes:
        raise SpeedTestError("response exceeded bounded sample")
    return data


def _mbps(byte_count: int, elapsed: float) -> Optional[float]:
    if byte_count <= 0 or elapsed <= 0:
        return None
    return round(byte_count * 8 / elapsed / 1_000_000, 2)


def _failure(mode: str, exc: Exception) -> Dict[str, Any]:
    return {
        "ok": False,
        "mode": mode,
        "endpoint": "Cloudflare",
        "status": "unknown",
        "error": type(exc).__name__,
        "traffic_warning": mode in {"download", "upload"},
        "raw_value_persisted": False,
    }


def measure_speed(mode: str, timeout: float = 5.0, size_bytes: int = _DEFAULT_BYTES) -> Dict[str, Any]:
    """Run one explicit latency, download, or upload observation.

    ``mode`` is deliberately closed-set.  Download/upload samples are capped
    at 1 MiB and report the traffic budget in the returned payload.
    """
    mode = str(mode or "").strip().lower()
    if mode not in {"latency", "download", "upload"}:
        raise ValueError("mode must be latency, download, or upload")
    timeout = _timeout(timeout)
    size = _size(size_bytes)
    try:
        if mode == "latency":
            samples = []
            for _ in range(_LATENCY_SAMPLES):
                started = time.perf_counter()
                _request("GET", _LATENCY_URL, body=None, timeout=timeout, max_bytes=64)
                samples.append(round((time.perf_counter() - started) * 1000, 2))
            return {
                "ok": True,
                "mode": mode,
                "endpoint": "Cloudflare",
                "latency_ms": round(float(median(samples)), 2),
                "jitter_ms": round(max(samples) - min(samples), 2),
                "samples": samples,
                "bytes": 1,
                "traffic_warning": False,
                "raw_value_persisted": False,
            }

        body = b"\0" * size if mode == "upload" else None
        url = _UPLOAD_URL if mode == "upload" else _DOWNLOAD_URL.format(size=size)
        started = time.perf_counter()
        data = _request(
            "POST" if mode == "upload" else "GET",
            url,
            body=body,
            timeout=timeout,
            max_bytes=64 if mode == "upload" else size,
        )
        elapsed = time.perf_counter() - started
        transferred = size if mode == "upload" else len(data)
        return {
            "ok": True,
            "mode": mode,
            "endpoint": "Cloudflare",
            "elapsed_ms": round(elapsed * 1000, 2),
            "mbps": _mbps(transferred, elapsed),
            "bytes": transferred,
            "traffic_warning": True,
            "raw_value_persisted": False,
        }
    except Exception as exc:  # noqa: BLE001 - failed measurement is unknown
        return _failure(mode, exc)


__all__ = ["SpeedTestError", "measure_speed"]
