"""Collector analysis for Claude Shield (AI-facing library).

Runs the read-only collector and turns the snapshot into structured audit
checks. Intended to be imported by an agent skill (Codex / Claude Code),
not invoked as a CLI. No output rendering lives here; agents format the
checks themselves per SKILL.md's Report Format.
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
from .models import AuditCheck, AuditReport, PlatformInfo, PrivacyMetadata, to_dict
from .redaction import Redactor
from .resources import resource_path
from .schema import validate_report


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
        else:
            script_path = resource_path("scripts", "collect_posix_network.sh")
            executable = shutil.which("bash")
            if not executable:
                raise CollectorError("bash is not available.")
            command = [executable, str(script_path)]

        result = subprocess.run(command, capture_output=True, timeout=timeout)
        if result.returncode != 0:
            error = Redactor().scan_and_redact(result.stderr.decode("utf-8", errors="replace").strip())
            raise CollectorError(f"collector exited with code {result.returncode}: {error}")
        stdout = result.stdout.decode("utf-8-sig", errors="replace")
        start = stdout.find("{")
        if start < 0:
            raise CollectorError("collector returned no JSON object")
        return json.loads(stdout[start:])
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        raise CollectorError(Redactor().scan_and_redact(str(exc))) from exc


def analyze_snapshot(data, include_recommendations=False, redactor=None):
    """Turn a collector snapshot into a list of AuditCheck objects.

    System-level checks run even when no Mihomo config is present. Returns
    a plain list; agents decide how to present it.
    """
    if not isinstance(data, dict):
        raise TypeError("snapshot must be a dictionary")

    builder = CheckBuilder(include_recommendations=include_recommendations)
    collect_privacy_checks(data, builder)
    collect_system_checks(data, builder)
    collect_browser_checks(data, builder)
    early_stop = collect_mihomo_checks(data, builder)
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


def run_full_audit(probe_timeout=5, include_recommendations=False, online=False):
    """One-call audit: run the collector, analyze locally, and optionally probe online.

    Returns a dict with:
    - ``checks``: list[AuditCheck]
    - ``summary``: severity counts
    - ``snapshot``: redacted collector JSON
    - ``report``: AuditReport dataclass
    - ``report_dict``: schema-validated plain dict (via models.to_dict)
    """
    from .probes.base import run_probes

    if online and (not isinstance(probe_timeout, (int, float)) or not 0 < probe_timeout <= 30):
        raise ValueError("Online probe timeout must be between 0 and 30 seconds.")

    snapshot = run_legacy_collector()
    redactor = Redactor()
    checks = analyze_snapshot(snapshot, include_recommendations=include_recommendations, redactor=redactor)
    try:
        probe_results = run_probes(None, timeout=probe_timeout, online=online)
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

    report = build_audit_report(checks, snapshot=snapshot, redactor=redactor)
    # Redact platform hostname in report before export
    report.platform.hostname = redactor.scan_and_redact(report.platform.hostname)
    report_dict = to_dict(report)
    validate_report(report_dict)

    return {
        "checks": checks,
        "summary": report.summary,
        "snapshot": redactor.scan_and_redact(snapshot),
        "report": report,
        "report_dict": report_dict,
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
]
