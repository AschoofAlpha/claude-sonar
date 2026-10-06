import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from claude_sonar.dimensions import build_dimension_matrix
from claude_sonar.models import AuditCheck


def check(check_id, status="pass", confidence="confirmed", recommendation=""):
    return AuditCheck(
        id=check_id,
        title=check_id,
        category="test",
        status=status,
        severity="info",
        confidence=confidence,
        recommendation=recommendation,
    )


def test_matrix_has_six_dimensions_and_conservative_unknowns():
    matrix = build_dimension_matrix([
        check("network.egress.runtime_consistency.example", recommendation="保持出口一致"),
        check("network.ip_reputation"),
        check("network.dns.egress_consistency"),
        check("network.tls.fingerprint"),
        check("network.ai_connectivity"),
    ])
    assert len(matrix["dimensions"]) == 6
    by_id = {item["id"]: item for item in matrix["dimensions"]}
    assert by_id["exit_network"]["status"] == "pass"
    # The available DNS check is a confirmed pass; uncovered signals remain
    # outside this dimension instead of being fabricated as failures.
    assert by_id["leak_detection"]["status"] == "pass"
    assert by_id["device_fingerprint"]["status"] == "pass"
    assert by_id["platform_reachability"]["status"] == "pass"
    assert by_id["browser_identity"]["status"] == "unknown"
    assert matrix["score"] is None
    assert matrix["score_kind"] == "dimension_status_matrix"


def test_fail_takes_precedence_and_raw_evidence_is_not_copied():
    item = check("network.teredo", status="fail", confidence="high", recommendation="关闭 Teredo")
    item.evidence = [{"address": "192.168.1.5"}]
    matrix = build_dimension_matrix([item])
    leak = next(d for d in matrix["dimensions"] if d["id"] == "leak_detection")
    assert leak["status"] == "fail"
    assert leak["evidence"] == [{"id": "network.teredo", "status": "fail", "confidence": "high"}]
    assert "192.168.1.5" not in json.dumps(matrix, ensure_ascii=False)


def test_warning_confidence_uses_warning_signal_only():
    matrix = build_dimension_matrix([
        check("network.dns", status="pass", confidence="confirmed"),
        check("network.dns_mode", status="warning", confidence="probable"),
    ])
    leak = next(d for d in matrix["dimensions"] if d["id"] == "leak_detection")
    assert leak["status"] == "warning"
    assert leak["confidence"] == "probable"


def test_empty_matrix_keeps_every_dimension_unknown():
    matrix = build_dimension_matrix([])
    assert all(item["status"] == "unknown" for item in matrix["dimensions"])
    assert matrix["summary"] == {"pass": 0, "warning": 0, "fail": 0, "unknown": 6}


def test_mapping_checks_are_supported():
    matrix = build_dimension_matrix([{"id": "network.ai_connectivity", "status": "pass", "confidence": "high"}])
    platform = next(d for d in matrix["dimensions"] if d["id"] == "platform_reachability")
    assert platform["status"] == "pass"
