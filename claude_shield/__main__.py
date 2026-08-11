"""CLI entry point: ``python -m claude_shield``.

Default output is a markdown report. Online probes stay off unless ``--online``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m claude_shield",
        description=(
            "Claude Shield — local privacy and proxy consistency audit. "
            "Online probes are disabled unless --online is passed."
        ),
    )
    parser.add_argument(
        "--online",
        action="store_true",
        default=False,
        help="Enable live egress/DNS/reputation/cross-site probes (off by default).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        dest="as_json",
        help="Print report_dict + summary as JSON instead of markdown.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="N",
        help="Probe timeout in seconds (default: 5). Only used with --online.",
    )
    parser.add_argument(
        "--intended-region",
        default=None,
        metavar="REGION",
        help="Optional intended exit region/country hint for online probes.",
    )
    parser.add_argument(
        "--intended-mode",
        choices=("system_proxy", "full_tunnel"),
        default=None,
        help=(
            "Optional intended proxy posture: system_proxy (OS proxy / mixed) "
            "or full_tunnel (TUN/global). Forwarded to analysis when supported."
        ),
    )
    parser.add_argument(
        "--lang",
        choices=("zh", "en"),
        default="zh",
        help="Plain-language layer for the markdown report (default: zh). Technical ids stay unchanged.",
    )
    parser.add_argument(
        "--out",
        default=None,
        metavar="PATH",
        help="Write the report to PATH (markdown, or JSON with --json). Also prints to stdout.",
    )
    parser.add_argument(
        "--diff",
        default=None,
        metavar="PATH",
        help="Previous JSON report (report_dict / CLI --json payload) to diff against this run.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        default=False,
        help="Shorter markdown report (score + must-fix / optional sections).",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        default=False,
        help="Full markdown report (default). Overrides --compact when both are set.",
    )
    return parser


def _write_out(path: str, text: str) -> None:
    target = Path(path)
    if target.parent and str(target.parent) not in ("", "."):
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _render_markdown(result, lang: str, compact: bool) -> str:
    from .report import format_report

    checks = result.get("checks") or []
    summary = result.get("summary")
    try:
        return format_report(checks, summary=summary, lang=lang, compact=compact)
    except TypeError:
        # Older format_report without compact=
        return format_report(checks, summary=summary, lang=lang)


def _append_diff_section(body: str, result, diff_path: str, lang: str, as_json: bool):
    """Load previous report and append / merge a diff section.

    For markdown: append a markdown section.
    For JSON: return a (text, payload) where payload gains a ``diff`` key.
    """
    from .diff import diff_reports, format_diff_markdown, load_previous_report

    try:
        previous = load_previous_report(diff_path)
    except Exception as exc:
        msg = f"diff error: could not load previous report {diff_path!r}: {exc}"
        print(msg, file=sys.stderr)
        if as_json:
            return body, None
        return body + f"\n\n> {msg}\n", None

    current_payload = result.get("report_dict") or {
        "checks": [
            {"id": getattr(c, "id", None), "status": getattr(c, "status", None), "severity": getattr(c, "severity", None)}
            for c in (result.get("checks") or [])
        ]
    }
    diff = diff_reports(previous, current_payload)
    if as_json:
        return body, diff
    section = format_diff_markdown(diff, lang=lang)
    if body and not body.endswith("\n"):
        body += "\n"
    return body + "\n" + section, diff


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.timeout is not None and not (0 < float(args.timeout) <= 30):
        parser.error("--timeout must be between 0 and 30 seconds")

    compact = bool(args.compact) and not bool(args.full)

    from .analyze import CollectorError, run_full_audit
    from .models import to_dict

    audit_kwargs = {
        "probe_timeout": args.timeout,
        "include_recommendations": True,
        "online": bool(args.online),
        "intended_region": args.intended_region,
        "lang": args.lang,
        "intended_mode": args.intended_mode,
    }

    try:
        try:
            result = run_full_audit(**audit_kwargs)
        except TypeError:
            # Older run_full_audit without intended_mode/lang — drop unknown kwargs.
            fallback = {
                k: v
                for k, v in audit_kwargs.items()
                if k in ("probe_timeout", "include_recommendations", "online", "intended_region", "lang")
            }
            try:
                result = run_full_audit(**fallback)
            except TypeError:
                fallback.pop("lang", None)
                result = run_full_audit(**fallback)
    except CollectorError as exc:
        print(f"collector error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - unexpected runtime failures
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.as_json:
        payload = {
            "report_dict": result.get("report_dict") or to_dict(result.get("report")),
            "summary": result.get("summary") or {},
        }
        text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        if args.diff:
            text, diff = _append_diff_section(text, result, args.diff, args.lang, as_json=True)
            if diff is not None:
                payload["diff"] = diff
                text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        if args.out:
            try:
                _write_out(args.out, text if text.endswith("\n") else text + "\n")
            except OSError as exc:
                print(f"error: could not write --out {args.out!r}: {exc}", file=sys.stderr)
                return 1
        print(text)
        return 0

    # Markdown path — always re-render with the requested plain-language layer.
    try:
        markdown = _render_markdown(result, lang=args.lang, compact=compact)
    except Exception:
        markdown = result.get("report_markdown") or (
            "# Claude Shield Audit Report\n\n(report unavailable)\n"
        )

    if args.diff:
        markdown, _diff = _append_diff_section(
            markdown, result, args.diff, args.lang, as_json=False
        )

    if args.out:
        try:
            out_text = markdown if markdown.endswith("\n") else markdown + "\n"
            _write_out(args.out, out_text)
        except OSError as exc:
            print(f"error: could not write --out {args.out!r}: {exc}", file=sys.stderr)
            return 1

    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
