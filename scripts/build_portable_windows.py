"""Build Claude Sonar's Windows one-file portable executable.

Run from any Python environment with PyInstaller installed:

    python scripts/build_portable_windows.py

The output is ``dist/ClaudeSonar.exe``. Build-time dependencies are not
runtime dependencies; the produced executable carries the Python runtime and
small read-only resources inside itself.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts" / "portable_entry.py"


def _data_args() -> list[str]:
    # Keep paths explicit: the frozen collector needs its PowerShell script,
    # and the BASE_URL probe needs its bundled risk-intel list.
    data = [
        (ROOT / "static" / "panel.html", Path("share") / "claude-sonar" / "static"),
        (ROOT / "claude_sonar" / "resources", Path("claude_sonar") / "resources"),
        (ROOT / "scripts" / "collect_windows_network.ps1", Path("share") / "claude-sonar" / "scripts"),
        (ROOT / "LICENSE", Path(".")),
    ]
    args: list[str] = []
    for source, destination in data:
        args.extend(["--add-data", f"{source}{os.pathsep}{destination}"])
    return args


def build() -> Path:
    if os.name != "nt":
        raise SystemExit("This builder targets Windows; run it on Windows.")
    if not ENTRY.is_file():
        raise FileNotFoundError(ENTRY)

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--console",
        "--name",
        "ClaudeSonar",
        "--paths",
        str(ROOT),
        "--distpath",
        str(ROOT / "dist"),
        "--workpath",
        str(ROOT / "build" / "pyinstaller"),
        "--specpath",
        str(ROOT / "build"),
        *_data_args(),
        str(ENTRY),
    ]
    subprocess.run(command, cwd=ROOT, check=True)
    artifact = ROOT / "dist" / "ClaudeSonar.exe"
    if not artifact.is_file():
        raise FileNotFoundError(f"PyInstaller completed without {artifact}")
    return artifact


def main() -> int:
    artifact = build()
    print(f"portable executable: {artifact}")
    print(f"size_bytes: {artifact.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
