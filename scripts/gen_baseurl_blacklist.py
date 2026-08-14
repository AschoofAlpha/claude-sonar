"""One-off generator: build claude_sonar/resources/known_baseurl_blacklist.txt.

Fetches the upstream risk-intel lists from CACEB001/Claude-Shield (main branch):
  - src/domains.rs  : plaintext DOMAIN_BLACKLIST (147 entries)
  - src/blobs.rs    : DOMAIN_BLOB (base64 + XOR 91 ciphertext of the same list)

Decodes the blob with the public XOR-91 algorithm, unions with the plaintext
list, dedupes and writes one domain per line. Pure data, no comments.

This script is a generator only; the runtime probe reads the .txt file and
never performs network fetches.
"""

from __future__ import annotations

import base64
import re
import sys
import urllib.request
from pathlib import Path

REPO = "https://raw.githubusercontent.com/CACEB001/Claude-Shield/main"
MAX_LINES = 300


def decode_xor91_blob(encoded: str) -> list:
    """base64-decode, XOR every byte with 91, split comma-separated domains."""
    raw = base64.b64decode(encoded.strip())
    text = bytes(b ^ 91 for b in raw).decode("utf-8", errors="replace")
    return [item.strip() for item in text.split(",") if item.strip()]


def _fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def main() -> int:
    out = Path(__file__).resolve().parent.parent / "claude_sonar" / "resources" / "known_baseurl_blacklist.txt"

    blob_src = _fetch(f"{REPO}/src/blobs.rs")
    dom_src = _fetch(f"{REPO}/src/domains.rs")

    blob = re.search(r'DOMAIN_BLOB: &str = "([^"]*)"', blob_src).group(1)
    decoded = decode_xor91_blob(blob)

    plain_match = re.search(r"DOMAIN_BLACKLIST: &\[&str\] = &\[(.*?)\];", dom_src, re.S)
    plain = re.findall(r'"([^"]+)"', plain_match.group(1))

    print(f"decoded blob entries : {len(decoded)}")
    print(f"plaintext entries    : {len(plain)}")
    print(f"identical            : {decoded == plain}")

    merged = []
    seen = set()
    for item in plain + decoded:
        if item not in seen:
            seen.add(item)
            merged.append(item)

    if len(merged) > MAX_LINES:
        # Fallback per task spec: keep common relay patterns only.
        merged = [
            "workers.dev",
            "zeabur.app",
            "fcapp.run",
            "vercel.app",
            "railway.app",
            "glitch.me",
            "replit.dev",
            "netlify.app",
        ]
        print(f"WARNING: list too large, downgraded to {len(merged)} common patterns")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(merged) + "\n", encoding="utf-8")
    print(f"wrote {len(merged)} lines -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
