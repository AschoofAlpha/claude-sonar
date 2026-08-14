"""reposcan 子模块数据模型。

完全独立于核心审计模块（probes/analysis/report/schema）：
Finding / StackInfo / ToolStatus / ScanResult 只服务于「代码仓库安全扫描」。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SEVERITIES = ("critical", "high", "medium", "low")
# 严重度排序权重（critical 最高），用于 baseline 恶化判定
_SEV_RANK = {s: len(SEVERITIES) - 1 - i for i, s in enumerate(SEVERITIES)}


def severity_rank(sev: str) -> int:
    """严重度排序权重（用于 baseline 恶化判定）。"""
    return _SEV_RANK.get(normalize_severity(sev), 0)


def normalize_severity(raw: Any) -> str:
    """把外部工具的各种严重度写法统一到 critical/high/medium/low。"""
    r = str(raw or "").strip().lower()
    if r in ("critical", "fatal"):
        return "critical"
    if r in ("high", "severe"):
        return "high"
    if r in ("medium", "moderate", "warning", "warn"):
        return "medium"
    if r in ("low", "info", "note", "informational"):
        return "low"
    return "low"


@dataclass
class Finding:
    """一条静态扫描/依赖审计发现。path 为相对目标目录的路径（用 / 分隔）。"""

    tool: str
    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    cwe: Optional[str] = None
    fingerprint: str = ""
    suggestion: str = ""

    def compute_fingerprint(self) -> str:
        """生成稳定指纹：同一处问题在两次扫描间保持一致（用于 baseline 对比）。"""
        raw = f"{self.tool}|{self.rule_id}|{self.path}|{self.line}|{self.message.strip()}"
        self.fingerprint = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]
        return self.fingerprint

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "cwe": self.cwe,
            "fingerprint": self.fingerprint,
            "suggestion": self.suggestion,
        }


@dataclass
class StackInfo:
    """检测到的语言 + 包管理器 + 依据文件（相对路径）。"""

    language: str
    package_manager: str
    files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "language": self.language,
            "package_manager": self.package_manager,
            "files": self.files,
        }


@dataclass
class ToolStatus:
    """外部工具的一次运行状态（graceful degradation 的载体）。"""

    name: str
    display: str
    available: bool
    status: str  # ok | skipped | error
    detail: str
    findings_count: int = 0
    install_hint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "display": self.display,
            "available": self.available,
            "status": self.status,
            "detail": self.detail,
            "findings_count": self.findings_count,
            "install_hint": self.install_hint,
        }


@dataclass
class ScanResult:
    """一次完整扫描的结果对象（json_out=True 时入口函数返回其 to_dict()）。"""

    target: str
    generated_at: str
    stack: List[StackInfo]
    tools: List[ToolStatus]
    findings: List[Finding]
    score: int
    grade: str
    grade_label: str
    distribution: Dict[str, int]
    baseline: Optional[Dict[str, Any]] = None
    sarif: Optional[Dict[str, Any]] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "reposcan/1",
            "generated_at": self.generated_at,
            "target": self.target,
            "stack": [s.to_dict() for s in self.stack],
            "tools": [t.to_dict() for t in self.tools],
            "findings": [f.to_dict() for f in self.findings],
            "score": self.score,
            "grade": self.grade,
            "grade_label": self.grade_label,
            "distribution": self.distribution,
            "baseline": self.baseline,
            "sarif": self.sarif,
            "notes": self.notes,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
