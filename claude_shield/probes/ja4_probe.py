"""JA3 / JA4 TLS client fingerprint observation via the system openssl.

Read-only measurement: runs ``openssl s_client -connect api.anthropic.com:443
-tlsextdebug -state -msg`` to capture the local ClientHello, then computes
the JA3 hash (Salesforce public spec) and the JA4 hash (FoxIO public spec,
https://github.com/FoxIO-LLC/ja4) in pure Python (stdlib only).

Tone contract: the fingerprint is reported as an *unknown fingerprint*
observation. It is never labeled good or bad, and this module deliberately
does NOT provide any fingerprint spoofing / fitting / byte-patching advice.
Missing openssl or a failed capture degrades to ``unknown`` — never a
failure and never an error.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Sequence, Tuple

from ..models import AuditCheck, Evidence

_ANTHROPIC_HOST = "api.anthropic.com"

# GREASE values: 0x0a0a, 0x1a1a, ..., 0xfafa (RFC 8701 pattern).
GREASE_VALUES = frozenset(0x0A0A + 0x1010 * k for k in range(16))

# JA4 version field mapping (TLS/DTLS; unknown -> "00").
_JA4_VERSIONS = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
    0xFEFC: "d3",
    0xFEFD: "d2",
    0xFEFF: "d1",
}

_SUPPORTED_VERSIONS = 0x002B
_SNI = 0x0000
_ALPN = 0x0010
_SIG_ALGS = 0x0013
_SUPPORTED_GROUPS = 0x000A
_EC_POINT_FORMATS = 0x000B


def is_grease(value: int) -> bool:
    return value in GREASE_VALUES


def find_openssl() -> Optional[str]:
    """Locate the openssl executable (works with git-bash openssl on Windows)."""
    return shutil.which("openssl")


def run_clienthello_capture(
    openssl_bin: str,
    host: str = _ANTHROPIC_HOST,
    timeout: int = 5,
) -> Tuple[bool, str]:
    """Run ``openssl s_client`` and return ``(captured_ok, raw_output)``.

    Never raises for probe-level failures: binary missing, non-zero exit,
    or timeout (partial handshake output is still returned on timeout).
    """
    cmd = [
        openssl_bin,
        "s_client",
        "-connect",
        f"{host}:443",
        "-servername",
        host,
        "-tlsextdebug",
        "-state",
        "-msg",
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except Exception as exc:  # pragma: no cover - environment dependent
        return False, f"openssl spawn failed: {exc}"
    try:
        out, _ = proc.communicate(timeout=max(1, int(timeout) or 1))
        return bool(out), out
    except subprocess.TimeoutExpired:
        # The ClientHello is usually captured long before the timeout;
        # keep whatever partial output we already have.
        try:
            proc.kill()
        except Exception:  # pragma: no cover
            pass
        out, _ = proc.communicate()
        return bool(out), out
    except Exception as exc:  # pragma: no cover
        return False, f"openssl run failed: {exc}"


def parse_clienthello_hex(text: str) -> Optional[bytes]:
    """Extract the first sent ClientHello hex dump from ``-msg`` output."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if "ClientHello" not in line or ">>>" not in line:
            continue
        tokens: List[str] = []
        for nxt in lines[i + 1:]:
            stripped = nxt.strip()
            if not stripped or stripped.startswith(">>>") or stripped.startswith("<<<"):
                break
            tokens.extend(stripped.split())
        cleaned = []
        for token in tokens:
            token = token.rstrip(":,")
            if re.fullmatch(r"[0-9a-fA-F]{2}", token):
                cleaned.append(token)
        if cleaned:
            return bytes(int(t, 16) for t in cleaned)
    return None


def _u16_list(data: Optional[bytes]) -> List[int]:
    if not data or len(data) < 2:
        return []
    total = int.from_bytes(data[0:2], "big")
    payload = data[2:2 + total]
    return [
        int.from_bytes(payload[i:i + 2], "big")
        for i in range(0, len(payload) - 1, 2)
    ]


def _parse_extensions(body: bytes, pos: int) -> Tuple[List[int], Dict[int, bytes]]:
    """Parse the ClientHello extensions block; returns (types, type->data)."""
    ext_types: List[int] = []
    ext_map: Dict[int, bytes] = {}
    if pos + 2 > len(body):
        return ext_types, ext_map
    total = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    end = min(pos + total, len(body))
    while pos + 4 <= end:
        etype = int.from_bytes(body[pos:pos + 2], "big")
        elen = int.from_bytes(body[pos + 2:pos + 4], "big")
        edata = body[pos + 4:pos + 4 + elen]
        ext_types.append(etype)
        ext_map[etype] = edata
        pos += 4 + elen
    return ext_types, ext_map


def parse_clienthello(raw: bytes) -> Dict[str, object]:
    """Parse a raw ClientHello (with or without the 4-byte handshake header)."""
    if not raw or len(raw) < 40:
        raise ValueError("ClientHello too short")
    offset = 4 if raw[0] == 0x01 else 0  # handshake header: type + 3-byte length
    body = raw[offset:]
    legacy_version = int.from_bytes(body[0:2], "big")
    pos = 2 + 32  # legacy_version + random
    pos += 1 + body[pos]  # session id
    ciphers_len = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    ciphers = [
        int.from_bytes(body[pos + i:pos + i + 2], "big")
        for i in range(0, ciphers_len, 2)
    ]
    pos += ciphers_len
    pos += 1 + body[pos]  # compression methods
    ext_types, ext_map = _parse_extensions(body, pos)
    return {
        "legacy_version": legacy_version,
        "ciphers": ciphers,
        "extensions": ext_types,
        "ext_map": ext_map,
    }


def ja3_fields(parsed: Dict[str, object]) -> str:
    """Build the pre-hash JA3 string (Salesforce layout, GREASE removed)."""
    version = int(parsed["legacy_version"])
    ciphers = [c for c in parsed["ciphers"] if not is_grease(int(c))]  # type: ignore[arg-type]
    exts = [e for e in parsed["extensions"] if not is_grease(int(e))]  # type: ignore[arg-type]
    curves = [v for v in _u16_list(parsed["ext_map"].get(_SUPPORTED_GROUPS)) if not is_grease(v)]
    points = [v for v in _u16_list(parsed["ext_map"].get(_EC_POINT_FORMATS)) if not is_grease(v)]
    return (
        f"{version},"
        f"{'-'.join(str(c) for c in ciphers)}-"
        f"{'-'.join(str(e) for e in exts)}-"
        f"{'-'.join(str(v) for v in curves)}-"
        f"{'-'.join(str(v) for v in points)}"
    )


def ja3_fingerprint(parsed: Dict[str, object]) -> str:
    return hashlib.md5(ja3_fields(parsed).encode("utf-8")).hexdigest()


def _u8_pair_list(data: Optional[bytes]) -> List[int]:
    """supported_versions (RFC 8446): 1-byte length prefix, then 2-byte values."""
    if not data or not data[0]:
        return []
    total = data[0]
    payload = data[1:1 + total]
    return [int.from_bytes(payload[i:i + 2], "big") for i in range(0, len(payload) - 1, 2)]


def _ja4_version(parsed: Dict[str, object]) -> int:
    versions = [
        v for v in _u8_pair_list(parsed["ext_map"].get(_SUPPORTED_VERSIONS))
        if not is_grease(v)
    ]
    if versions:
        return max(versions)
    return int(parsed["legacy_version"])


def _alpn_chars(data: Optional[bytes]) -> str:
    if not data or len(data) < 2:
        return "00"
    total = int.from_bytes(data[0:2], "big")
    pos = 2
    end = min(2 + total, len(data))
    if pos >= end:
        return "00"
    nlen = data[pos]
    pos += 1
    val = data[pos:pos + nlen]
    if not val:
        return "00"

    def _char(b: int) -> str:
        if 0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A:
            return chr(b)
        return f"{b:02x}"

    return _char(val[0]) + _char(val[-1])


def _ja4_cipher_hash(ciphers: Sequence[int]) -> str:
    listed = sorted(f"{c:04x}" for c in ciphers)
    if not listed:
        return "000000000000"
    return hashlib.sha256(",".join(listed).encode("utf-8")).hexdigest()[:12]


def _ja4_extension_hash(
    exts: Sequence[int],
    sig_algs: Sequence[int],
) -> str:
    listed = sorted(f"{e:04x}" for e in exts if e not in (_SNI, _ALPN))
    if not listed:
        return "000000000000"
    joined = ",".join(listed)
    if sig_algs:
        joined += "_" + ",".join(f"{s:04x}" for s in sig_algs)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:12]


def ja4_fingerprint(parsed: Dict[str, object]) -> str:
    """Compute the JA4 fingerprint (FoxIO public spec, truncated hashes)."""
    version = _ja4_version(parsed)
    vchar = _JA4_VERSIONS.get(version, "00")
    sni = "d" if _SNI in parsed["ext_map"] else "i"
    ciphers = [c for c in parsed["ciphers"] if not is_grease(int(c))]  # type: ignore[arg-type]
    exts = [e for e in parsed["extensions"] if not is_grease(int(e))]  # type: ignore[arg-type]
    count_c = f"{min(len(ciphers), 99):02d}"
    count_e = f"{min(len(exts), 99):02d}"
    alpn = _alpn_chars(parsed["ext_map"].get(_ALPN))
    sig_algs = [s for s in _u16_list(parsed["ext_map"].get(_SIG_ALGS)) if not is_grease(s)]
    c_hash = _ja4_cipher_hash(ciphers)
    e_hash = _ja4_extension_hash(exts, sig_algs)
    return f"t{vchar}{sni}{count_c}{count_e}{alpn}_{c_hash}_{e_hash}"


def check_tls_fingerprint(timeout: int = 5) -> AuditCheck:
    """Observe the local TLS ClientHello fingerprint (JA3/JA4, read-only)."""
    base_kwargs = dict(
        id="network.tls.fingerprint",
        title="TLS client fingerprint (JA3/JA4, read-only)",
        category="network",
    )

    openssl_bin = find_openssl()
    if not openssl_bin:
        return AuditCheck(
            status="unknown",
            severity="info",
            confidence="unknown",
            explanation=(
                "[openssl_missing] 未找到 openssl 可执行文件，无法抓取本机 TLS "
                "ClientHello 指纹（JA3/JA4）。这不是安全问题；安装 openssl 后"
                "可再次运行本检测。"
            ),
            **base_kwargs,
        )

    captured, output = run_clienthello_capture(openssl_bin, _ANTHROPIC_HOST, timeout)
    raw = parse_clienthello_hex(output) if captured else None
    if raw is None:
        return AuditCheck(
            status="unknown",
            severity="info",
            confidence="unknown",
            explanation=(
                "[capture_failed] openssl 已运行，但未从输出中抓到 ClientHello"
                "（可能是网络被代理/防火墙拦截，或 openssl 版本输出格式不同）。"
                "本次只读检测未得出指纹。"
            ),
            **base_kwargs,
        )

    try:
        parsed = parse_clienthello(raw)
        ja3 = ja3_fingerprint(parsed)
        ja4 = ja4_fingerprint(parsed)
        evidence_data = {
            "ja3": ja3,
            "ja4": ja4,
            "target": _ANTHROPIC_HOST,
            "tls_version": _ja4_version(parsed),
            "cipher_count": len(parsed["ciphers"]),
            "extension_count": len(parsed["extensions"]),
            "raw_clienthello_persisted": False,
            "spoof_advice": "not_provided",
        }
    except Exception:
        return AuditCheck(
            status="unknown",
            severity="info",
            confidence="unknown",
            explanation=(
                "[parse_failed] 已抓到 ClientHello 但解析失败（openssl 输出格式"
                "与预期不符）。本次只读检测未得出指纹。"
            ),
            **base_kwargs,
        )

    return AuditCheck(
        status="unknown",
        severity="info",
        confidence="possible",
        evidence=[Evidence(
            type="tls_fingerprint",
            description="TLS client fingerprint observation (read-only, no spoof advice)",
            data=evidence_data,
        )],
        explanation=(
            f"只读检测：本机 openssl 连接 {_ANTHROPIC_HOST} 的 TLS ClientHello 指纹为 "
            f"JA3={ja3}、JA4={ja4}（未知指纹：指纹本身不代表异常，仅供观察）。"
            "本工具不提供指纹伪装、拟合或修改建议。"
        ),
        **base_kwargs,
    )
