"""内置精简 Semgrep 规则集加载器。

规则文件位于 claude_shield/resources/semgrep_rules/（精简自
alissonlinneker/shield-claude-skill，MIT，详见同目录 NOTICE.md）。
semgrep 未安装时，扫描流程会给出 `semgrep --config <规则目录>` 的手动用法提示。
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Set

# 栈检测语言 -> 规则文件名（未收录的语言返回 None，走兜底逻辑）
_LANG_RULE_MAP = {
    "python": "python.yaml",
    "javascript": "javascript.yaml",
    "typescript": "javascript.yaml",
    "javascript/typescript": "javascript.yaml",
    "go": "go.yaml",
    "rust": "rust.yaml",
    "java": "java.yaml",
    "kotlin": "java.yaml",
    "ruby": "ruby.yaml",
    "php": "php.yaml",
    "csharp": "csharp.yaml",
    "c#": "csharp.yaml",
}

_NOTICE = "NOTICE.md"


def rules_dir() -> Path:
    """内置规则目录（源码检出与 wheel 安装下均位于包内）。"""
    return Path(__file__).resolve().parent.parent / "resources" / "semgrep_rules"


def available_rule_files() -> List[Path]:
    """目录下全部规则文件（不含 NOTICE），按文件名排序。"""
    d = rules_dir()
    if not d.is_dir():
        return []
    return sorted(p for p in d.glob("*.yaml") if p.name != _NOTICE)


def rule_files_for_languages(languages: Set[str]) -> List[Path]:
    """按检测到的语言挑选规则文件；全部未命中时回退到完整内置规则集。"""
    chosen: List[Path] = []
    for lang in sorted(languages):
        key = str(lang).strip().lower()
        name = _LANG_RULE_MAP.get(key)
        if not name:
            continue
        f = rules_dir() / name
        if f.is_file() and f not in chosen:
            chosen.append(f)
    return chosen or available_rule_files()


def manual_semgrep_hint(target: str, rule_files: Optional[List[Path]] = None) -> str:
    """semgrep 未安装时的手动运行提示。"""
    configs = rule_files or available_rule_files()
    if configs:
        cfg = " ".join(f'--config "{p}"' for p in configs)
    else:
        cfg = f'--config "{rules_dir()}"'
    return f"可手动运行：semgrep {cfg} \"{target}\""
