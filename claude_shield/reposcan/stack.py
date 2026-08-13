"""技术栈检测：扫描目标目录的 lockfile / manifest 识别语言与包管理器。"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import StackInfo

# 精确文件名 -> (语言, 包管理器)
_EXACT: Dict[str, Tuple[str, str]] = {
    "package.json": ("JavaScript/TypeScript", "npm"),
    "pnpm-lock.yaml": ("JavaScript/TypeScript", "pnpm"),
    "yarn.lock": ("JavaScript/TypeScript", "yarn"),
    "bun.lockb": ("JavaScript/TypeScript", "bun"),
    "bun.lock": ("JavaScript/TypeScript", "bun"),
    "requirements.txt": ("Python", "pip"),
    "pyproject.toml": ("Python", "pip"),
    "Pipfile": ("Python", "pipenv"),
    "poetry.lock": ("Python", "Poetry"),
    "uv.lock": ("Python", "uv"),
    "Cargo.toml": ("Rust", "cargo"),
    "Cargo.lock": ("Rust", "cargo"),
    "go.mod": ("Go", "go modules"),
    "go.sum": ("Go", "go modules"),
    "Gemfile": ("Ruby", "bundler"),
    "Gemfile.lock": ("Ruby", "bundler"),
    "composer.json": ("PHP", "composer"),
    "composer.lock": ("PHP", "composer"),
    "pom.xml": ("Java", "maven"),
    "build.gradle": ("Java", "gradle"),
    "build.gradle.kts": ("Java", "gradle"),
    "packages.config": ("C#", "nuget"),
    "pubspec.yaml": ("Dart", "pub"),
    "Package.swift": ("Swift", "swiftpm"),
}

# glob 匹配 -> (语言, 包管理器)
_GLOBS: List[Tuple[str, str, str]] = [
    ("*.csproj", "C#", "nuget"),
    ("*.vbproj", "C#", "nuget"),
    ("*.nuspec", "C#", "nuget"),
    ("*.sln", "C#", "nuget"),
    ("setup.py", "Python", "pip"),
    ("setup.cfg", "Python", "pip"),
]

# 无 manifest 时的源码兜底：扩展名 -> (语言, 包管理器)
_SOURCE_EXT: Dict[str, Tuple[str, str]] = {
    ".py": ("Python", "pip"),
    ".js": ("JavaScript/TypeScript", "npm"),
    ".ts": ("JavaScript/TypeScript", "npm"),
    ".jsx": ("JavaScript/TypeScript", "npm"),
    ".tsx": ("JavaScript/TypeScript", "npm"),
    ".go": ("Go", "go modules"),
    ".rs": ("Rust", "cargo"),
    ".java": ("Java", "maven"),
    ".kt": ("Java", "gradle"),
    ".rb": ("Ruby", "bundler"),
    ".php": ("PHP", "composer"),
    ".cs": ("C#", "nuget"),
}

# 绝对跳过的目录（依赖目录/虚拟环境/构建产物）
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    "venv", ".venv", "env", ".env", "site-packages",
    "__pycache__", "dist", "build", "target", ".idea", ".vscode", ".mypy_cache",
    ".pytest_cache", ".tox", ".eggs",
})


def _rel(root: Path, p: Path) -> str:
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return p.as_posix()


def _refine_pyproject(root: Path, pyproject: Path) -> str:
    """根据 pyproject.toml 内容细化 Python 包管理器。"""
    try:
        head = pyproject.read_text(encoding="utf-8", errors="replace")[:4000].lower()
    except OSError:
        return "pip"
    if "[tool.poetry" in head:
        return "Poetry"
    if "[tool.uv" in head or "requires-python" in head and "uv" in head:
        return "uv"
    return "pip"


def scan_stack(target: Path) -> List[StackInfo]:
    """扫描目录，返回去重合并后的技术栈列表（按语言名排序）。

    同语言多种包管理器会合并为一条（如 Python: pip + Poetry），
    便于报告展示；semgrep 规则选择只关心语言本身。
    """
    target = Path(target)
    by_language: Dict[str, Dict[str, object]] = {}
    # 源码扩展名计数（无 manifest 时的兜底）
    src_counts: Dict[str, Dict[str, int]] = {}

    for dirpath, dirnames, filenames in os.walk(str(target)):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        base = Path(dirpath)
        for fn in filenames:
            full = base / fn
            rel = _rel(target, full)

            matched: Optional[Tuple[str, str]] = None
            if fn in _EXACT:
                matched = _EXACT[fn]
            else:
                for pattern, lang, pm in _GLOBS:
                    if fnmatch.fnmatch(fn, pattern):
                        matched = (lang, pm)
                        break

            if matched is not None:
                lang, pm = matched
                if fn == "pyproject.toml":
                    pm = _refine_pyproject(target, full)
                entry = by_language.setdefault(
                    lang, {"package_managers": set(), "files": []}
                )
                entry["package_managers"].add(pm)  # type: ignore[attr-defined]
                entry["files"].append(rel)  # type: ignore[attr-defined]

            ext = full.suffix.lower()
            if ext in _SOURCE_EXT:
                lang = _SOURCE_EXT[ext][0]
                src_counts.setdefault(lang, {}).setdefault(ext, 0)
                src_counts[lang][ext] += 1

    # 无 manifest 的语言用源码兜底（标注「源码检测」）
    for lang, exts in src_counts.items():
        if lang not in by_language:
            total = sum(exts.values())
            if total > 0:
                detail = "、".join(f"{n} 个 {e} 文件" for e, n in sorted(exts.items()))
                by_language[lang] = {
                    "package_managers": {"(源码检测)"},
                    "files": [detail],
                }

    result: List[StackInfo] = []
    for lang in sorted(by_language):
        entry = by_language[lang]
        pms = sorted(entry["package_managers"])  # type: ignore[arg-type]
        files = sorted(set(entry["files"]))  # type: ignore[arg-type]
        result.append(StackInfo(
            language=lang,
            package_manager=" + ".join(pms),
            files=files[:20],
        ))
    return result
