"""SARIF 2.1.0 导出（OASIS Static Analysis Results Interchange Format）。

输出最小但合规的结构：version + runs[].tool.driver + results[]（含 ruleId、
level、message、physicalLocation）。严重度映射：critical/high -> error，
medium -> warning，low -> note。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def findings_to_sarif(result: Dict[str, Any], tool_version: str = "") -> Dict[str, Any]:
    """把扫描结果 dict 转成 SARIF 2.1.0 对象（结果不依赖任何第三方库）。"""
    findings = result.get("findings") or []
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        rule_id = str(f.get("rule_id") or f"{f.get('tool')}:unknown")
        sev = str(f.get("severity") or "low")
        if rule_id not in rules:
            message = str(f.get("message") or rule_id)
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": message[:120]},
                "fullDescription": {"text": message},
                "defaultConfiguration": {"level": _LEVELS.get(sev, "note")},
            }
            cwe = f.get("cwe")
            if cwe:
                rules[rule_id]["properties"] = {"cwe": cwe, "tool": f.get("tool")}

        line = int(f.get("line") or 0)
        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": str(f.get("path") or "").replace("\\", "/"),
                },
            }
        }
        if line > 0:
            location["physicalLocation"]["region"] = {
                "startLine": line,
                "startColumn": 1,
            }
        results.append({
            "ruleId": rule_id,
            "ruleIndex": list(rules).index(rule_id),
            "level": _LEVELS.get(sev, "note"),
            "message": {"text": str(f.get("message") or "")[:500]},
            "locations": [location],
            "properties": {
                "tool": str(f.get("tool") or ""),
                "severity": sev,
                "fingerprint": str(f.get("fingerprint") or ""),
            },
        })

    driver: Dict[str, Any] = {
        "name": "claude-shield-reposcan",
        "informationUri": "https://github.com/AschoofAlpha/claude-shield",
        "rules": [rules[k] for k in rules],
    }
    if tool_version:
        driver["semanticVersion"] = str(tool_version)
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": driver},
            "results": results,
        }],
    }


def write_sarif(path: Any, sarif: Dict[str, Any]) -> Path:
    """写出 SARIF 文件（UTF-8、缩进 2），返回实际路径。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(sarif, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return p
