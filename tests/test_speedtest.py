"""Unit tests for bounded fixed-endpoint speed observations."""

import pytest

from claude_sonar.probes import speedtest


def test_request_rejects_hostname_that_only_contains_fixed_host(monkeypatch):
    class FailingOpener:
        def open(self, *args, **kwargs):
            raise AssertionError("network opener must not be reached")

    monkeypatch.setattr(speedtest, "_OPENER", FailingOpener())
    with pytest.raises(speedtest.SpeedTestError, match="fixed endpoint validation failed"):
        speedtest._request(
            "GET",
            "https://evil.example/speed.cloudflare.com",
            body=None,
            timeout=1.0,
            max_bytes=1,
        )


def test_size_is_bounded_to_the_declared_traffic_limit():
    assert speedtest._size(1) == 64 * 1024
    assert speedtest._size(256 * 1024) == 256 * 1024
    assert speedtest._size(99 * 1024 * 1024) == speedtest._MAX_BYTES
