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
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    serve_p = sub.add_parser(
        "serve", help="Start the read-only local web panel on 127.0.0.1."
    )
    serve_p.add_argument(
        "--port", type=int, default=8765, metavar="N",
        help="Panel port (default: 8765).",
    )
    serve_p.add_argument(
        "--open", action="store_true",
        help="Open the panel in the default browser after start.",
    )
    repo_p = sub.add_parser(
        "repo", help="Security-scan a local code repository (SAST/secrets/deps)."
    )
    repo_p.add_argument("path", metavar="PATH", help="Repository directory to scan.")
    repo_p.add_argument(
        "--no-tools", action="store_true",
        help="Skip external tools (semgrep/gitleaks/audit); stack detection only.",
    )
    repo_p.add_argument(
        "--baseline", default=None, metavar="PATH",
        help="Previous scan JSON to diff against.",
    )
    repo_p.add_argument(
        "--json", action="store_true", dest="as_json",
        help="Print the scan result as JSON instead of markdown.",
    )
    repo_p.add_argument(
        "--sarif", default=None, metavar="PATH",
        help="Also export SARIF 2.1.0 to PATH.",
    )
    repo_p.add_argument(
        "--out", default=None, metavar="PATH",
        help="Write the report to PATH (also printed to stdout).",
    )
    badge_p = sub.add_parser(
        "badge", help="Write shield-badge.json from an audit result."
    )
    badge_p.add_argument(
        "--out", default=None, metavar="PATH",
        help="Badge JSON path (default: repo-root shield-badge.json).",
    )
    badge_p.add_argument(
        "--from-report", default=None, dest="from_report", metavar="PATH",
        help="Read a previous --json report for the score instead of re-auditing.",
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
    # The snapshot drives proxy-client personalization; without it the
    # "detected proxy" section degrades to "unknown client".
    snapshot = result.get("snapshot")
    try:
        return format_report(
            checks, summary=summary, lang=lang, compact=compact, snapshot=snapshot
        )
    except TypeError:
        # Older format_report without compact= / snapshot=
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


def _cmd_serve(args) -> int:
    from .serve import serve

    port = int(args.port)
    if not (1024 <= port <= 65535):
        print(f"error: --port must be between 1024 and 65535 (got {port})", file=sys.stderr)
        return 2
    try:
        httpd = serve(port=port, open_browser=bool(args.open))
    except OSError as exc:
        print(f"error: could not start panel on 127.0.0.1:{port}: {exc}", file=sys.stderr)
        return 1
    print(f"Claude Shield panel: http://127.0.0.1:{port}/  (read-only; Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\npanel stopped")
    finally:
        httpd.server_close()
    return 0


def _cmd_repo(args) -> int:
    from .reposcan.scanner import result_to_report, run_repo_scan

    try:
        result = run_repo_scan(
            args.path,
            use_tools=not bool(args.no_tools),
            baseline_path=args.baseline,
            json_out=bool(args.as_json),
            sarif_path=args.sarif,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if isinstance(result, dict):
        text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
    else:
        text = result_to_report(result)
    if not text.endswith("\n"):
        text += "\n"
    if args.out:
        try:
            _write_out(args.out, text)
        except OSError as exc:
            print(f"error: could not write --out {args.out!r}: {exc}", file=sys.stderr)
            return 1
    print(text, end="")
    return 0


def _cmd_badge(args) -> int:
    from .badge import default_badge_path, make_badge, score_from_result

    out = Path(args.out) if args.out else default_badge_path()
    score = None
    if args.from_report:
        try:
            payload = json.loads(Path(args.from_report).read_text(encoding="utf-8"))
            if isinstance(payload, dict) and "report_dict" in payload:
                payload = payload["report_dict"]
            score = score_from_result(payload)
        except Exception as exc:
            print(f"error: could not read --from-report {args.from_report!r}: {exc}", file=sys.stderr)
            return 1
    if score is None:
        from .analyze import run_full_audit

        try:
            result = run_full_audit(probe_timeout=5, online=False)
        except Exception as exc:
            print(f"error: audit failed: {exc}", file=sys.stderr)
            return 1
        score = score_from_result(result)
    if score is None:
        print("error: could not derive a score from the audit result", file=sys.stderr)
        return 1
    try:
        data = make_badge(score, str(out))
    except OSError as exc:
        print(f"error: could not write badge {out}: {exc}", file=sys.stderr)
        return 1
    print(f"badge written: {out}  ({data.get('message')})")
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "repo":
        return _cmd_repo(args)
    if args.command == "badge":
        return _cmd_badge(args)

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
