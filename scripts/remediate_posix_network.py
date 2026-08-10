#!/usr/bin/env python3
"""POSIX privacy-env remediation (Python; replaces remediate_posix_network.sh).

Preview by default. Writes only ~/.claude-shield/claude-code-privacy.env after
--apply. Never touches shell profiles, DNS, routes, or device identifiers.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ENV_LINES = (
    "export DISABLE_TELEMETRY=1",
    "export DISABLE_ERROR_REPORTING=1",
    "export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
)


def _base_dir() -> Path:
    return Path.home() / ".claude-shield"


def _env_file() -> Path:
    return _base_dir() / "claude-code-privacy.env"


def _backup_dir() -> Path:
    return _base_dir() / "backups"


def _managed_content() -> str:
    return "\n".join(ENV_LINES) + "\n"


def cmd_preview() -> int:
    print("Plan only: create a local file containing the documented Claude Code privacy opt-outs.")
    print(f"Target: {_env_file()}")
    print("No shell profile, network adapter, DNS, route, cache, or device identifier will be changed.")
    return 0


def cmd_apply() -> int:
    base = _base_dir()
    backups = _backup_dir()
    env_file = _env_file()
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    backups.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(base, stat.S_IRWXU)
    os.chmod(backups, stat.S_IRWXU)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_base = backups / f"claude-code-privacy.{stamp}.{os.getpid()}"
    if env_file.is_file():
        backup = Path(str(backup_base) + ".env")
        backup.write_bytes(env_file.read_bytes())
    else:
        backup = Path(str(backup_base) + ".absent")
        backup.write_text("", encoding="utf-8")
    os.chmod(backup, stat.S_IRUSR | stat.S_IWUSR)

    fd, tmp_name = tempfile.mkstemp(prefix=".privacy-env.", dir=str(base))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(_managed_content())
        os.chmod(tmp_name, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp_name, env_file)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)

    print(f"Created {env_file}")
    print(f"To apply in the current shell, run: source {env_file}")
    print(f"Rollback: {Path(__file__).name} --restore {backup}")
    return 0


def cmd_restore(backup: str) -> int:
    backup_path = Path(backup).resolve()
    expected_parent = _backup_dir().resolve()
    if backup_path.parent != expected_parent:
        print(f"Restore file must be inside {_backup_dir()}", file=sys.stderr)
        return 2
    if not backup_path.is_file():
        print(f"Backup not found: {backup_path}", file=sys.stderr)
        return 2

    env_file = _env_file()
    managed = _managed_content()
    if env_file.is_file():
        current = env_file.read_text(encoding="utf-8")
        if current != managed:
            print(f"Refusing to overwrite a modified {env_file}", file=sys.stderr)
            return 2

    if backup_path.name.endswith(".absent"):
        if env_file.exists():
            env_file.unlink()
        print(f"Removed managed file {env_file}")
    else:
        env_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        env_file.write_bytes(backup_path.read_bytes())
        os.chmod(env_file, stat.S_IRUSR | stat.S_IWUSR)
        print(f"Restored {env_file} from {backup_path}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Claude Shield POSIX privacy-env remediation")
    parser.add_argument("--apply", action="store_true", help="Write the environment file")
    parser.add_argument("--restore", metavar="BACKUP", help="Restore from a backup under ~/.claude-shield/backups")
    args = parser.parse_args(argv)

    if args.apply and args.restore:
        print("Use either --apply or --restore, not both.", file=sys.stderr)
        return 2
    if args.apply:
        return cmd_apply()
    if args.restore:
        return cmd_restore(args.restore)
    return cmd_preview()


if __name__ == "__main__":
    raise SystemExit(main())
