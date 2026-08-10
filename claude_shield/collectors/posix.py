"""Limited read-only POSIX collector (replaces collect_posix_network.sh).

Emits the same SchemaVersion 7 shape: OS/platform marker, proxy-env presence
only (no values), and Claude Code privacy-control presence/active flags.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone


def _present(name: str) -> bool:
    return name in os.environ


def _active_one(name: str) -> bool:
    return os.environ.get(name, "") == "1"


def _active_content(name: str) -> bool:
    value = os.environ.get(name, "")
    return value == "1" or value.startswith("file:")


def _privacy_rows(name: str, mode: str = "one") -> list:
    present = _present(name)
    if mode == "content":
        active = _active_content(name) if present else False
    else:
        active = _active_one(name) if present else False
    return [{"Scope": "Process", "Present": present, "Active": active}]


def _privacy_pair(env_name: str, key: str, mode: str = "one") -> dict:
    rows = _privacy_rows(env_name, mode=mode)
    active = bool(rows and rows[0].get("Active"))
    return {f"{key}Vars": rows, f"{key}Active": active}


def collect_posix_snapshot() -> dict:
    """Return a limited POSIX collector snapshot (dict, not JSON text)."""
    claude = {}
    claude.update(_privacy_pair("DISABLE_TELEMETRY", "DisableTelemetry"))
    claude.update(_privacy_pair("DISABLE_ERROR_REPORTING", "DisableErrorReporting"))
    claude.update(
        _privacy_pair(
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
            "DisableNonessentialTraffic",
        )
    )
    claude.update(_privacy_pair("CLAUDE_CODE_SKIP_PROMPT_HISTORY", "SkipPromptHistory"))
    claude.update(_privacy_pair("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB", "SubprocessEnvScrub"))
    claude.update(_privacy_pair("OTEL_LOG_USER_PROMPTS", "OtelLogUserPrompts"))
    claude.update(_privacy_pair("OTEL_LOG_TOOL_CONTENT", "OtelLogToolContent"))
    claude.update(_privacy_pair("OTEL_LOG_TOOL_DETAILS", "OtelLogToolDetails"))
    claude.update(_privacy_pair("OTEL_LOG_RAW_API_BODIES", "OtelLogRawApiBodies", mode="content"))

    proxy_names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy")
    # Deduplicate case variants for reporting presence only once per canonical upper name
    seen = set()
    proxy_rows = []
    for name in proxy_names:
        canon = name.upper()
        if canon in seen:
            continue
        seen.add(canon)
        proxy_rows.append({"Name": canon, "Present": _present(name) or _present(canon)})

    return {
        "SchemaVersion": 7,
        "CollectedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "System": {
            "Platform": "POSIX",
            "ProxyEnvironmentVariables": proxy_rows,
        },
        "ClaudeCode": claude,
    }


def main(argv=None) -> int:
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--self-test"]:
        # Minimal behavioral parity with the old bash self-test.
        os.environ.pop("CLAUDE_SHIELD_SELFTEST_ENV", None)
        os.environ["CLAUDE_SHIELD_SELFTEST_ENV"] = "not-one"
        assert _present("CLAUDE_SHIELD_SELFTEST_ENV") is True
        assert _active_one("CLAUDE_SHIELD_SELFTEST_ENV") is False
        os.environ["CLAUDE_SHIELD_SELFTEST_ENV"] = "1"
        assert _active_one("CLAUDE_SHIELD_SELFTEST_ENV") is True
        os.environ["CLAUDE_SHIELD_SELFTEST_ENV"] = "file:/private/trace"
        assert _active_content("CLAUDE_SHIELD_SELFTEST_ENV") is True
        rows = _privacy_rows("CLAUDE_SHIELD_SELFTEST_ENV", mode="content")
        blob = json.dumps(rows)
        assert "private" not in blob and "trace" not in blob and '"Value"' not in blob
        print("Self-test passed.")
        return 0

    print(json.dumps(collect_posix_snapshot(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
