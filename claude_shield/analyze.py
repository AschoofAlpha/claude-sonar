"""Collector analysis for Claude Shield (AI-facing library).

Runs the read-only collector and turns the snapshot into structured audit
checks. Also powers ``python -m claude_shield``. Agents may format checks via
``format_report`` (see ``claude_shield.report``).
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone

from .__version__ import __version__
from .analysis import (
    CheckBuilder,
    collect_browser_checks,
    collect_mihomo_checks,
    collect_privacy_checks,
    collect_system_checks,
    mihomo_protects_dns,
    redact_checks,
)
from .analysis.system import merge_geo_with_egress, normalize_intended_mode
from .models import AuditCheck, AuditReport, PlatformInfo, PrivacyMetadata, to_dict
from .redaction import Redactor
from .resources import resource_path
from .schema import validate_report

try:
    from .report import format_report
except ImportError:  # pragma: no cover
    format_report = None  # type: ignore[assignment]


class CollectorError(RuntimeError):
    """Raised when the platform collector fails."""


def run_legacy_collector(timeout=30):
    """Run the platform collector and return its parsed JSON snapshot.

    Raises CollectorError on missing runtime, non-zero exit, timeout, or
    unparseable output. Never prints or exits the process.
    """
    try:
        if os.name == "nt":
            script_path = resource_path("scripts", "collect_windows_network.ps1")
            executable = shutil.which("pwsh") or shutil.which("powershell.exe")
            if not executable:
                raise CollectorError("PowerShell is not available.")
            command = [
                executable,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
            ]
            result = subprocess.run(command, capture_output=True, timeout=timeout)
            if result.returncode != 0:
                error = Redactor().scan_and_redact(result.stderr.decode("utf-8", errors="replace").strip())
                raise CollectorError(f"collector exited with code {result.returncode}: {error}")
            stdout = result.stdout.decode("utf-8-sig", errors="replace")
            start = stdout.find("{")
            if start < 0:
                raise CollectorError("collector returned no JSON object")
            return json.loads(stdout[start:])

        # POSIX / macOS / Linux: pure-Python limited collector (no bash).
        from .collectors.posix import collect_posix_snapshot

        return collect_posix_snapshot()
    except CollectorError:
        raise
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        raise CollectorError(Redactor().scan_and_redact(str(exc))) from exc
    except Exception as exc:  # pragma: no cover - unexpected collector failures
        raise CollectorError(Redactor().scan_and_redact(str(exc))) from exc


def analyze_snapshot(data, include_recommendations=True, redactor=None, intended_mode=None, **_kwargs):
    """Turn a collector snapshot into a list of AuditCheck objects.

    System-level checks run even when no Mihomo config is present. Returns
    a plain list; agents decide how to present it (or use ``format_report``).

    ``intended_mode`` is optional (``system_proxy`` / ``full_tunnel``; aliases
    ``system-proxy``, ``tun``, ``full-tunnel``) and is forwarded to collectors
    that accept it; unknown kwargs are ignored.
    """
    if not isinstance(data, dict):
        raise TypeError("snapshot must be a dictionary")

    mode = normalize_intended_mode(intended_mode)
    builder = CheckBuilder(include_recommendations=include_recommendations)
    # intended_mode is a coordination stub for analysis collectors; pass only
    # when the callee accepts it so older analysis modules keep working.
    def _call(fn, *args):
        try:
            return fn(*args, intended_mode=mode)
        except TypeError:
            return fn(*args)

    _call(collect_privacy_checks, data, builder)
    try:
        from .personalize import collect_client_profile_check
        collect_client_profile_check(data, builder)
    except Exception:
        pass
    _call(collect_system_checks, data, builder)
    _call(collect_browser_checks, data, builder)
    early_stop = _call(collect_mihomo_checks, data, builder)
    # early_stop True means no mihomo config; checks already include placeholder
    _ = early_stop
    return redact_checks(builder.checks, redactor or Redactor())


def summarize(checks):
    """Count checks by severity. Returns a dict with the standard keys."""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for check in checks:
        summary[check.severity] = summary.get(check.severity, 0) + 1
    return summary


# Back-compat aliases used by older tests/imports
from .analysis.common import is_local_or_fake_dns as _is_local_or_fake_dns
_redact_checks = redact_checks


def build_audit_report(checks, snapshot=None, redactor=None):
    """Assemble a schema-validatable AuditReport from checks (+ optional snapshot)."""
    system = snapshot.get("System") if isinstance(snapshot, dict) else {}
    if not isinstance(system, dict):
        system = {}
    host = str(system.get("ComputerName") or system.get("Hostname") or platform.node() or "unknown")
    os_name = str(system.get("OS") or platform.system() or "unknown")
    os_version = str(system.get("OSVersion") or platform.version() or "")
    report = AuditReport(
        schema_version="1.0",
        tool_version=__version__,
        generated_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        platform=PlatformInfo(os=os_name, version=os_version, hostname=host),
        privacy=PrivacyMetadata(
            redaction_enabled=True,
            salt_used=bool(getattr(redactor, "salt", None)),
        ),
        checks=list(checks),
        summary=summarize(checks),
        errors=[],
    )
    return report


def run_full_audit(
    probe_timeout=5,
    include_recommendations=True,
    online=False,
    intended_region=None,
    cross_site_urls=None,
    lang="zh",
    intended_mode=None,
    compact=False,
):
    """One-call audit: run the collector, analyze locally, and optionally probe online.

    Returns a dict with:
    - ``checks``: list[AuditCheck]
    - ``summary``: severity counts
    - ``snapshot``: redacted collector JSON
    - ``report``: AuditReport dataclass
    - ``report_dict``: schema-validated plain dict (via models.to_dict)
    - ``report_markdown``: markdown string from ``format_report`` when available

    ``lang`` selects the plain-language layer for ``report_markdown`` (``zh`` or ``en``).
    ``intended_mode`` is optional (``system_proxy`` / ``full_tunnel``) and is
    forwarded into ``analyze_snapshot`` when collectors support it.
    ``compact`` shortens ``report_markdown`` when the formatter supports it.
    """
    from .probes.base import run_probes

    if online and (not isinstance(probe_timeout, (int, float)) or not 0 < probe_timeout <= 30):
        raise ValueError("Online probe timeout must be between 0 and 30 seconds.")

    snapshot = run_legacy_collector()
    redactor = Redactor()
    checks = analyze_snapshot(
        snapshot,
        include_recommendations=include_recommendations,
        redactor=redactor,
        intended_mode=intended_mode,
    )
    try:
        probe_kwargs = {
            "timeout": probe_timeout,
            "online": online,
            "intended_region": intended_region,
            "cross_site_urls": cross_site_urls,
        }
        probe_results = run_probes(None, **probe_kwargs)
        checks.extend(redact_checks(probe_results, redactor))
    except Exception as exc:  # probes are best-effort; never fail the audit
        checks.extend(redact_checks([AuditCheck(
            id="network.egress.probe_error",
            title="Online probe failure",
            category="network",
            status="unknown",
            severity="info",
            confidence="unknown",
            explanation=f"Online probes could not run: {exc}",
        )], redactor))

    # Best-effort: fold online reputation country into offline geo_stack message
    checks = merge_geo_with_egress(checks)

    report = build_audit_report(checks, snapshot=snapshot, redactor=redactor)
    # Redact platform hostname in report before export
    report.platform.hostname = redactor.scan_and_redact(report.platform.hostname)
    report_dict = to_dict(report)
    validate_report(report_dict)

    report_markdown = None
    formatter = format_report
    if formatter is None:
        try:
            from .report import format_report as formatter
        except ImportError:
            formatter = None
    if formatter is not None:
        try:
            report_markdown = formatter(
                checks,
                summary=report.summary,
                lang=lang,
                compact=compact,
                snapshot=snapshot,
                intended_mode=intended_mode,
                intended_region=intended_region,
            )
        except TypeError:
            try:
                report_markdown = formatter(checks, summary=report.summary, lang=lang)
            except Exception:
                report_markdown = None
        except Exception:
            report_markdown = None

    return {
        "checks": checks,
        "summary": report.summary,
        "snapshot": redactor.scan_and_redact(snapshot),
        "report": report,
        "report_dict": report_dict,
        "report_markdown": report_markdown,
    }


# Re-export for tests that import helpers from analyze
__all__ = [
    "CollectorError",
    "run_legacy_collector",
    "analyze_snapshot",
    "summarize",
    "run_full_audit",
    "build_audit_report",
    "mihomo_protects_dns",
    "_is_local_or_fake_dns",
    "_redact_checks",
    "format_report",
]
