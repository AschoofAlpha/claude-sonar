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
]
