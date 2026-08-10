"""CLI entry point: ``python -m claude_shield``.

Default output is a markdown report. Online probes stay off unless ``--online``.
"""

from __future__ import annotations

import argparse
import json
import sys


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
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.timeout is not None and not (0 < float(args.timeout) <= 30):
        parser.error("--timeout must be between 0 and 30 seconds")

    from .analyze import CollectorError, run_full_audit
    from .models import to_dict

    try:
        result = run_full_audit(
            probe_timeout=args.timeout,
            include_recommendations=True,
            online=bool(args.online),
            intended_region=args.intended_region,
        )
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
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        return 0

    markdown = result.get("report_markdown")
    if not markdown:
        try:
            from .report import format_report

            markdown = format_report(result.get("checks") or [])
        except Exception:
            markdown = "# Claude Shield Audit Report\n\n(report unavailable)\n"
    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
