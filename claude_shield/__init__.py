"""Claude Shield — local privacy and proxy consistency audit library."""

from .__version__ import __version__

try:
    from .analyze import (
        CollectorError,
        analyze_snapshot,
        build_audit_report,
        run_full_audit,
        run_legacy_collector,
        summarize,
    )
    from .models import AuditCheck, AuditReport, Evidence
    from .redaction import Redactor
except ImportError:  # pragma: no cover - allow version-only import during packaging edge cases
    pass

try:
    from .personalize import (
        build_personal_guidance,
        detect_active_proxy,
        detect_cli_agent,
        format_personal_section,
    )
    from .report import format_report, group_checks, plain_check, plain_status, score_checks
except ImportError:  # pragma: no cover
    format_report = None  # type: ignore[assignment]
    group_checks = None  # type: ignore[assignment]
    plain_check = None  # type: ignore[assignment]
    plain_status = None  # type: ignore[assignment]
    score_checks = None  # type: ignore[assignment]

try:
    from .diff import (
        diff_audits,
        diff_reports,
        format_diff_markdown,
        load_checks_from_report_dict,
        load_previous_report,
    )
except ImportError:  # pragma: no cover
    diff_audits = None  # type: ignore[assignment]
    diff_reports = None  # type: ignore[assignment]
    format_diff_markdown = None  # type: ignore[assignment]
    load_checks_from_report_dict = None  # type: ignore[assignment]
    load_previous_report = None  # type: ignore[assignment]

__all__ = [
    "__version__",
    "CollectorError",
    "run_legacy_collector",
    "analyze_snapshot",
    "run_full_audit",
    "build_audit_report",
    "summarize",
    "AuditCheck",
    "AuditReport",
    "Evidence",
    "Redactor",
    "format_report",
    "group_checks",
    "score_checks",
    "plain_check",
    "plain_status",
    "diff_audits",
    "diff_reports",
    "format_diff_markdown",
    "load_checks_from_report_dict",
    "load_previous_report",
]
