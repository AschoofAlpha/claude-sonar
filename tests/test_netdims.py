"""Tests for the absorbed read-only network dimensions.

Covers: ANTHROPIC_BASE_URL audit (3-state + blacklist), DNS egress vs HTTP
egress consistency (degrade paths + mocked match/mismatch), JA4/JA3 TLS
fingerprint (spec vectors, ClientHello parsing, openssl-missing / capture
failure degrade paths), and the supported_versions 1-byte-prefix regression.
"""
from __future__ import annotations

import base64
import hashlib

import pytest

from claude_shield.probes import baseurl_probe, dns_egress_probe, ja4_probe
from claude_shield.probes.baseurl_probe import (
    check_anthropic_baseurl,
    decode_xor91_blob,
    find_blacklist_hit,
)
from claude_shield.probes.dns_egress_probe import check_dns_egress_consistency
from claude_shield.probes.ja4_probe import (
    _ja4_cipher_hash,
    _ja4_extension_hash,
    _u8_pair_list,
    check_tls_fingerprint,
    ja3_fields,
    ja3_fingerprint,
    ja4_fingerprint,
    parse_clienthello,
    parse_clienthello_hex,
)

# --------------------------------------------------------------------------
# ANTHROPIC_BASE_URL audit
# --------------------------------------------------------------------------


def test_decode_xor91_blob_fixed_sample():
    plain = ["cn", "sankuai.com", "163.com", "wolfai.top"]
    blob = base64.b64encode(
        bytes(b ^ 91 for b in ",".join(plain).encode())
    ).decode()
    assert decode_xor91_blob(blob) == plain


def test_find_blacklist_hit_suffix_matching():
    entries = ["wolfai.top"]
    assert find_blacklist_hit("api.wolfai.top", entries) == "wolfai.top"
    assert find_blacklist_hit("wolfai.top", entries) == "wolfai.top"
    assert find_blacklist_hit("evil.com", entries) is None


def test_baseurl_unset_is_not_configured(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    check = check_anthropic_baseurl()
    assert check.id == "network.anthropic_baseurl"
    assert check.status == "pass"
    assert "[not_configured]" in check.explanation


def test_baseurl_official_is_pass(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
    check = check_anthropic_baseurl()
    assert check.status == "pass"
    assert check.evidence[0].data["host_class"] == "official"


def test_baseurl_custom_is_warning(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://relay.example.com")
    check = check_anthropic_baseurl()
    assert check.status == "warning"
    assert check.severity == "low"
    assert check.evidence[0].data["host_class"] == "custom"


def test_baseurl_blacklist_hit_is_high_warning(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://api.wolfai.top")
    monkeypatch.setattr(baseurl_probe, "load_blacklist", lambda: ["wolfai.top"])
    check = check_anthropic_baseurl()
    assert check.status == "warning"
    assert check.severity == "high"
    assert check.evidence[0].data["blacklist_hit"] is True


def test_baseurl_unparseable_is_warning(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "://")
    check = check_anthropic_baseurl()
    assert check.status == "warning"
    assert check.evidence[0].data["host_class"] == "unparseable"


# --------------------------------------------------------------------------
# DNS egress consistency
# --------------------------------------------------------------------------


def test_dns_doh_unavailable_degrades_to_unknown(monkeypatch):
    monkeypatch.setattr(dns_egress_probe, "fetch_doh_exit_ip", lambda timeout: None)
    monkeypatch.setattr(
        dns_egress_probe, "observe_egress_url",
        lambda url, timeout, redactor: {"ok": True, "observed_address": "tok1"},
    )
    check = check_dns_egress_consistency(timeout=1)
    assert check.status == "unknown"
    assert "[doh_unavailable]" in check.explanation


def test_dns_match_is_pass(monkeypatch):
    monkeypatch.setattr(dns_egress_probe, "fetch_doh_exit_ip", lambda timeout: "8.8.8.8")
    monkeypatch.setattr(
        dns_egress_probe,
        "_redact_token",
        lambda ip, redactor: "same-token" if ip else None,
    )
    monkeypatch.setattr(
        dns_egress_probe, "observe_egress_url",
        lambda url, timeout, redactor: {"ok": True, "observed_address": "same-token"},
    )
    check = check_dns_egress_consistency(timeout=1)
    assert check.status == "pass"
    assert check.evidence[0].data["match"] is True


def test_dns_mismatch_is_warning(monkeypatch):
    monkeypatch.setattr(dns_egress_probe, "fetch_doh_exit_ip", lambda timeout: "8.8.8.8")
    monkeypatch.setattr(
        dns_egress_probe,
        "_redact_token",
        lambda ip, redactor: "doh-token" if ip else None,
    )
    monkeypatch.setattr(
        dns_egress_probe, "observe_egress_url",
        lambda url, timeout, redactor: {"ok": True, "observed_address": "http-token"},
    )
    check = check_dns_egress_consistency(timeout=1)
    assert check.status == "warning"
    assert check.severity == "low"
    assert check.evidence[0].data["match"] is False


# --------------------------------------------------------------------------
# JA4 / JA3 TLS fingerprint
# --------------------------------------------------------------------------


def test_u8_pair_list_supported_versions_prefix_regression():
    # RFC 8446 supported_versions: 04 0304 0303 -> [0x0304, 0x0303]
    assert _u8_pair_list(bytes.fromhex("0403040303")) == [0x0304, 0x0303]
    assert _u8_pair_list(None) == []
    assert _u8_pair_list(b"") == []


def test_ja4_cipher_hash_spec_vectors():
    ciphers = [0x002F, 0x0035, 0x009C, 0x009D, 0x1301, 0x1302, 0x1303,
               0xC013, 0xC014, 0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9]
    assert _ja4_cipher_hash(ciphers) == "8daaf6152771"
    assert _ja4_cipher_hash([]) == "000000000000"


def test_ja4_extension_hash_spec_vectors():
    exts = [0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D,
            0x0005, 0x0023, 0x0012, 0x002B, 0xFF01, 0x000B, 0x000A, 0x0015]
    sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    assert _ja4_extension_hash(exts, sigs) == "e5627efa2ab1"
    assert _ja4_extension_hash(exts, []) == "6d807ffa2a79"
    assert _ja4_extension_hash([], []) == "000000000000"


def _build_hello() -> bytes:
    legacy = bytes.fromhex("0303")
    random_ = bytes(32)
    sess = bytes([0])
    ciphers = bytes.fromhex("000413011302")  # 0x1301, 0x1302
    comp = bytes([1, 0])
    sni = bytes.fromhex("000000080006000003616263")
    groups = bytes.fromhex("000a00040002001d")
    alpn = bytes.fromhex("001000050003026832")
    exts = sni + groups + alpn
    body = legacy + random_ + sess + ciphers + comp + len(exts).to_bytes(2, "big") + exts
    hs = bytes([1]) + len(body).to_bytes(3, "big") + body
    return hs


def test_parse_clienthello_synthetic():
    parsed = parse_clienthello(_build_hello())
    assert parsed["legacy_version"] == 0x0303
    assert parsed["ciphers"] == [0x1301, 0x1302]
    assert parsed["extensions"] == [0, 10, 16]


def test_ja3_synthetic_fields():
    parsed = parse_clienthello(_build_hello())
    j3 = ja3_fields(parsed)
    assert j3 == "771,4865-4866-0-10-16-29-"
    assert ja3_fingerprint(parsed) == hashlib.md5(j3.encode()).hexdigest()


def test_ja4_synthetic():
    parsed = parse_clienthello(_build_hello())
    j4 = ja4_fingerprint(parsed)
    assert j4.startswith("t12d0203h2_")
    assert j4.endswith("_" + _ja4_extension_hash([0, 10, 16], []))


def test_parse_clienthello_hex_dump():
    raw = _build_hello()
    lines = [
        "    " + " ".join(f"{x:02x}" for x in raw[i:i + 16])
        for i in range(0, len(raw), 16)
    ]
    text = ">>> TLS 1.2, Handshake [length 0038], ClientHello\n" + "\n".join(lines)
    assert parse_clienthello_hex(text) == raw


def test_tls_openssl_missing_degrades(monkeypatch):
    monkeypatch.setattr(ja4_probe, "find_openssl", lambda: None)
    check = check_tls_fingerprint(timeout=1)
    assert check.status == "unknown"
    assert "[openssl_missing]" in check.explanation


def test_tls_capture_failed_degrades(monkeypatch):
    monkeypatch.setattr(ja4_probe, "find_openssl", lambda: "/usr/bin/openssl")
    monkeypatch.setattr(
        ja4_probe, "run_clienthello_capture",
        lambda bin_, host, timeout: (False, ""),
    )
    check = check_tls_fingerprint(timeout=1)
    assert check.status == "unknown"
    assert "[capture_failed]" in check.explanation


def test_tls_success_path(monkeypatch):
    raw = _build_hello()
    lines = [
        "    " + " ".join(f"{x:02x}" for x in raw[i:i + 16])
        for i in range(0, len(raw), 16)
    ]
    text = ">>> TLS 1.2, Handshake [length 0038], ClientHello\n" + "\n".join(lines)
    monkeypatch.setattr(ja4_probe, "find_openssl", lambda: "/usr/bin/openssl")
    monkeypatch.setattr(
        ja4_probe, "run_clienthello_capture",
        lambda bin_, host, timeout: (True, text),
    )
    check = check_tls_fingerprint(timeout=1)
    assert check.status == "unknown"  # neutral: an observed fingerprint is never a verdict
    assert check.confidence == "possible"
    data = check.evidence[0].data
    assert data["ja4"].startswith("t12d0203h2_")
    assert data["spoof_advice"] == "not_provided"
    assert data["raw_clienthello_persisted"] is False
