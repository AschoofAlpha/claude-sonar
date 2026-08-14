"""Upload claude-sonar dist artifacts to PyPI via the legacy API (no twine)."""
import hashlib
import os
import sys

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN = open(os.path.join(ROOT, ".pypi-token.txt"), encoding="utf-8").read().strip()
assert TOKEN.startswith("pypi-"), "token format"

DIST = os.path.join(ROOT, "dist")
PROXIES = {"http": "http://127.0.0.1:7897", "https": "http://127.0.0.1:7897"}

for fname in sorted(os.listdir(DIST)):
    if not (fname.endswith(".whl") or fname.endswith(".tar.gz")):
        continue
    path = os.path.join(DIST, fname)
    data = open(path, "rb").read()
    ftype = "bdist_wheel" if fname.endswith(".whl") else "sdist"
    form = {
        ":action": "file_upload",
        "protocol_version": "1",
        "name": "claude-sonar",
        "version": "1.0.0",
        "filetype": ftype,
        "pyversion": "py3" if ftype == "bdist_wheel" else "source",
        "metadata_version": "2.4",
        "sha256_digest": hashlib.sha256(data).hexdigest(),
    }
    r = requests.post(
        "https://upload.pypi.org/legacy/",
        data=form,
        files={"content": (fname, data)},
        auth=("__token__", TOKEN),
        proxies=PROXIES,
        timeout=180,
    )
    print(f"{fname}: HTTP {r.status_code}")
    if r.status_code != 200:
        print(r.text[:600])
        sys.exit(1)
print("UPLOAD OK")
