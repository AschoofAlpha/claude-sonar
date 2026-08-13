"""Quick self-check of the new probe math against public-spec vectors."""
import sys, hashlib
sys.path.insert(0, ".")

from claude_shield.probes.ja4_probe import (
    _ja4_cipher_hash, _ja4_extension_hash, parse_clienthello,
    parse_clienthello_hex, ja3_fields, ja3_fingerprint, ja4_fingerprint,
    is_grease,
)
from claude_shield.probes.baseurl_probe import decode_xor91_blob

# 1) JA4 spec known-answer vectors
cipher_list = [0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
               0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9]
assert _ja4_cipher_hash(cipher_list) == "8daaf6152771", _ja4_cipher_hash(cipher_list)

ext_list = [0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
            0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015]
sig_list = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
assert _ja4_extension_hash(ext_list, sig_list) == "e5627efa2ab1", _ja4_extension_hash(ext_list, sig_list)
assert _ja4_extension_hash(ext_list, []) == "6d807ffa2a79", _ja4_extension_hash(ext_list, [])
assert _ja4_cipher_hash([]) == "000000000000"
assert _ja4_extension_hash([], []) == "000000000000"
print("JA4 spec vectors OK")

# 2) Synthetic ClientHello: TLS1.3, SNI, 2 ciphers, 2 extensions (SNI + groups), ALPN h2
def build_hello():
    # handshake body
    legacy = bytes.fromhex("0303")
    random = bytes(32)
    sess = bytes([0])
    ciphers = bytes.fromhex("000413011302")          # len 4: 0x1301, 0x1302
    comp = bytes([1, 0])
    # SNI ext: type 0000, len 0008, payload: listlen 0006, type 00, namelen 0003, "abc"
    sni = bytes.fromhex("000000080006000003616263")
    # groups ext: 000a, len 0004, listlen 0002, 001d (x25519)
    groups = bytes.fromhex("000a00040002001d")
    # ALPN ext: 0010, len 0005, listlen 0003, len 02, "h2"
    alpn = bytes.fromhex("001000050003026832")
    exts = sni + groups + alpn
    body = legacy + random + sess + ciphers + comp + len(exts).to_bytes(2, "big") + exts
    hs = bytes([1]) + len(body).to_bytes(3, "big") + body
    return hs

raw = build_hello()
parsed = parse_clienthello(raw)
assert parsed["legacy_version"] == 0x0303
assert parsed["ciphers"] == [0x1301, 0x1302]
assert parsed["extensions"] == [0, 10, 16]

j3 = ja3_fields(parsed)
expected_j3 = "771,4865-4866-0-10-16-29-"
assert j3 == expected_j3, j3
assert ja3_fingerprint(parsed) == hashlib.md5(expected_j3.encode()).hexdigest()

j4 = ja4_fingerprint(parsed)
assert j4.startswith("t12d0203h2_"), j4
assert j4.endswith("_" + _ja4_extension_hash([0, 10, 16], [])), j4
print("synthetic JA3 fields:", j3)
print("synthetic JA4:", j4)
print("JA3 md5:", ja3_fingerprint(parsed))

# 3) hex dump parsing
def hexdump(b):
    out = []
    for i in range(0, len(b), 16):
        out.append("    " + " ".join(f"{x:02x}" for x in b[i:i+16]))
    return "\n".join(out)

text = ">>> TLS 1.2, Handshake [length 0038], ClientHello\n" + hexdump(raw) + "\n<<< TLS 1.2, Handshake [length 0002], ServerHello\n0102\n"
assert parse_clienthello_hex(text) == raw
print("hex parse OK")

# 4) base64+XOR91 decoder with fixed sample
plain = ["cn", "sankuai.com", "163.com", "wolfai.top"]
import base64
blob = base64.b64encode(bytes(b ^ 91 for b in ",".join(plain).encode())).decode()
assert decode_xor91_blob(blob) == plain
print("xor91 decode OK")

# 5) GREASE
assert is_grease(0x0a0a) and is_grease(0xfafa) and not is_grease(0x1301)
print("all self-checks OK")
