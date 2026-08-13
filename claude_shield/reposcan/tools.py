"""外部工具编排：semgrep / gitleaks / pip-audit / npm audit。

设计原则（graceful degradation，吸收 shield-claude-skill 的「缺工具跳过并注明」）：
- 先用 shutil.which 探测工具；未安装 -> 状态 skipped + 安装命令提示，绝不报错退出。
- subprocess 一律 list args + shell=False + timeout（Windows 兼容）。
- 工具返回非零退出码并不一定是失败（semgrep/gitleaks 检出问题时也非零），
  以「输出能否解析」为准。
- 任何异常都折叠为 ToolStatus(status="error")，带人类可读说明。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .models import Finding, ToolStatus, normalize_severity
from .rules import manual_semgrep_hint, rule_files_for_languages

_DEFAULT_TIMEOUTS = {
    "semgrep": 900,
    "gitleaks": 600,
    "pip-audit": 300,
    "npm": 300,
}

_INSTALL_HINTS = {
    "semgrep": "pip install semgrep",
    "gitleaks": "winget install gitleaks.gitleaks（macOS: brew install gitleaks；Linux: go install github.com/gitleaks/gitleaks/v8@latest）",
    "pip-audit": "pip install pip-audit",
    "npm": "随 Node.js 一起安装：https://nodejs.org/（npm install -g npm 可升级）",
}

# semgrep 的 ERROR/WARNING/INFO -> 统一严重度（ERROR 视为高危而非严重，避免评分失真）
_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _which(name: str) -> Optional[str]:
    """模块级工具探测（测试可 monkeypatch）。Windows 下自动匹配 .exe/.cmd。"""
    return shutil.which(name)


def _run(
    cmd: Sequence[str],
    timeout: int,
    cwd: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """模块级 subprocess 调用（测试可 monkeypatch）。shell=False + timeout。"""
    env = dict(os.environ)
    env.setdefault("SEMGREP_SEND_METRICS", "off")
    return subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        timeout=timeout,
        cwd=cwd,
        env=env,
    )


def _rel_path(p: Any, target: Path) -> str:
    """把工具给出的路径转成相对目标目录、/ 分隔的形式。"""
    raw = str(p or "").strip()
    if not raw:
        return ""
    abs_p = os.path.abspath(raw)
    target_abs = os.path.abspath(str(target))
    try:
        common = os.path.commonpath([abs_p, target_abs])
    except ValueError:
        common = ""
    if common == target_abs:
        return os.path.relpath(abs_p, target_abs).replace("\\", "/")
    return raw.replace("\\", "/")


def _mask_secret(secret: str, keep: int = 10) -> str:
    """报告里只展示密钥前几个字符，避免二次泄露。"""
    s = (secret or "").strip()
    if len(s) <= keep + 1:
        return s or "?"
    return s[:keep] + "…"


class ToolRunner:
    """按需调用外部工具；每个方法返回 (findings, status)，永不抛异常。"""

    def __init__(self, target: Path, timeout_override: Optional[Dict[str, int]] = None):
        self.target = Path(target)
        self.timeouts = dict(_DEFAULT_TIMEOUTS)
        if timeout_override:
            self.timeouts.update(timeout_override)

    # ------------------------------------------------------------------ 基础

    def _safe_run(
        self, cmd: Sequence[str], tool: str, cwd: Optional[str] = None
    ) -> Tuple[bool, str, str, int, str]:
        """执行命令并把异常折叠为 (ok, stdout, stderr, returncode, error)。"""
        try:
            proc = _run(cmd, timeout=self.timeouts.get(tool, 300), cwd=cwd)
            return True, proc.stdout or "", proc.stderr or "", proc.returncode, ""
        except subprocess.TimeoutExpired:
            t = self.timeouts.get(tool, 300)
            return False, "", f"执行超时（>{t}s）", -1, "timeout"
        except OSError as exc:
            return False, "", f"无法执行：{exc}", -1, "oserror"
        except Exception as exc:  # 兜底：绝不把异常抛给上层
            return False, "", f"执行出错：{exc}", -1, "error"

    def _status(self, name: str, display: str, status: str, detail: str,
                findings_count: int = 0, available: Optional[bool] = None,
                hint: str = "") -> ToolStatus:
        if available is None:
            available = status == "ok"
        return ToolStatus(
            name=name, display=display, available=available, status=status,
            detail=detail, findings_count=findings_count,
            install_hint=hint if status != "ok" else "",
        )

    # --------------------------------------------------------------- semgrep

    def run_semgrep(
        self, rule_files: Sequence[Path], target_display: Optional[str] = None
    ) -> Tuple[List[Finding], ToolStatus]:
        """SAST 扫描。未安装时返回 skipped + 手动运行提示。"""
        target_display = target_display or str(self.target)
        exe = _which("semgrep")
        if not exe:
            hint = _INSTALL_HINTS["semgrep"] + "；" + manual_semgrep_hint(
                target_display, list(rule_files)
            )
            return [], self._status(
                "semgrep", "semgrep（SAST 静态分析）", "skipped",
                "工具未安装，本次跳过静态分析", available=False, hint=hint,
            )
        if not rule_files:
            return [], self._status(
                "semgrep", "semgrep（SAST 静态分析）", "skipped",
                "内置规则集缺失（resources/semgrep_rules/ 为空）",
                available=True,
            )

        configs: List[str] = []
        for f in rule_files:
            configs += ["--config", str(f)]
        cmd = [exe, "scan", "--json", "--quiet"] + configs + [str(self.target)]
        ok, out, err, rc, err_kind = self._safe_run(cmd, "semgrep")
        findings, warnings, parsed = self._parse_semgrep(out)

        if ok and not parsed and rc >= 2:
            # 旧版 semgrep 没有 `scan` 子命令：回退一次旧式调用
            cmd2 = [exe, "--json", "--quiet"] + configs + [str(self.target)]
            ok, out, err, rc, err_kind = self._safe_run(cmd2, "semgrep")
            findings, warnings, parsed = self._parse_semgrep(out)

        if not ok:
            return [], self._status(
                "semgrep", "semgrep（SAST 静态分析）", "error", err,
                available=True,
            )
        if not parsed:
            detail = f"输出无法解析（退出码 {rc}）"
            if err.strip():
                detail += f"：{err.strip()[:160]}"
            return [], self._status(
                "semgrep", "semgrep（SAST 静态分析）", "error", detail,
                available=True,
            )
        detail = f"已完成，检出 {len(findings)} 项"
        if warnings:
            detail += f"（另有 {len(warnings)} 条规则/文件解析提示）"
        return findings, self._status(
            "semgrep", "semgrep（SAST 静态分析）", "ok", detail,
            findings_count=len(findings), available=True,
        )

    def _parse_semgrep(
        self, stdout: str
    ) -> Tuple[List[Finding], List[str], bool]:
        """解析 semgrep --json 输出；非 JSON 时返回 parsed=False。"""
        if not stdout.strip():
            return [], [], False
        try:
            data = json.loads(stdout)
        except (ValueError, TypeError):
            return [], [], False
        findings: List[Finding] = []
        for r in data.get("results", []) or []:
            extra = r.get("extra") or {}
            meta = extra.get("metadata") or {}
            raw_sev = extra.get("severity") or meta.get("severity") or "WARNING"
            sev = _SEMGREP_SEV.get(str(raw_sev).upper(), "low")
            cwe = meta.get("cwe")
            if isinstance(cwe, list):
                cwe = ", ".join(str(c) for c in cwe)
            f = Finding(
                tool="semgrep",
                rule_id=str(r.get("check_id") or "unknown"),
                severity=sev,
                path=_rel_path(r.get("path"), self.target),
                line=int((r.get("start") or {}).get("line") or 0),
                message=(extra.get("message") or "").strip(),
                cwe=str(cwe) if cwe else None,
            )
            findings.append(f)
        warnings = [str(e.get("message") or "")[:120] for e in (data.get("errors") or [])]
        return findings, warnings, True

    # -------------------------------------------------------------- gitleaks

    def run_gitleaks(self) -> Tuple[List[Finding], ToolStatus]:
        """密钥扫描（含 git 历史，无 .git 时退化为纯文件扫描）。"""
        exe = _which("gitleaks")
        if not exe:
            return [], self._status(
                "gitleaks", "gitleaks（密钥/敏感信息扫描）", "skipped",
                "工具未安装，本次跳过密钥扫描", available=False,
                hint=_INSTALL_HINTS["gitleaks"],
            )
        fd, tmp = tempfile.mkstemp(prefix="claude-shield-gitleaks-", suffix=".json")
        os.close(fd)
        try:
            cmd = [
                exe, "detect",
                "--source", str(self.target),
                "--report-format", "json",
                "--report-path", tmp,
            ]
            if not (self.target / ".git").is_dir():
                cmd.append("--no-git")
            ok, out, err, rc, err_kind = self._safe_run(cmd, "gitleaks")

            findings: List[Finding] = []
            if os.path.exists(tmp) and os.path.getsize(tmp) > 0:
                findings = self._parse_gitleaks(tmp)

            if not ok:
                return [], self._status(
                    "gitleaks", "gitleaks（密钥/敏感信息扫描）", "error", err,
                    available=True,
                )
            if rc not in (0, 1):
                detail = f"异常退出（退出码 {rc}）"
                if err.strip():
                    detail += f"：{err.strip()[:160]}"
                return [], self._status(
                    "gitleaks", "gitleaks（密钥/敏感信息扫描）", "error", detail,
                    available=True,
                )
            detail = f"已完成，检出 {len(findings)} 项"
            return findings, self._status(
                "gitleaks", "gitleaks（密钥/敏感信息扫描）", "ok", detail,
                findings_count=len(findings), available=True,
            )
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _parse_gitleaks(self, report_path: str) -> List[Finding]:
        try:
            with open(report_path, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (ValueError, OSError, TypeError):
            return []
        findings: List[Finding] = []
        for item in data if isinstance(data, list) else []:
            rule_id = str(item.get("RuleID") or item.get("rule_id") or "secret")
            secret = _mask_secret(str(item.get("Secret") or item.get("Match") or ""))
            entropy = item.get("Entropy")
            msg = f"疑似硬编码密钥（{rule_id}）：{secret}"
            if entropy is not None:
                msg += f"（熵 {entropy}）"
            f = Finding(
                tool="gitleaks",
                rule_id=f"gitleaks:{rule_id}",
                severity="high",
                path=_rel_path(item.get("File"), self.target),
                line=int(item.get("StartLine") or 0),
                message=msg,
                cwe="CWE-798",
            )
            findings.append(f)
        return findings

    # ------------------------------------------------------------- pip-audit

    def run_pip_audit(self, python_detected: bool) -> Tuple[List[Finding], ToolStatus]:
        """Python 依赖审计。无 Python 栈或依赖清单时跳过。"""
        if not python_detected:
            return [], self._status(
                "pip-audit", "pip-audit（Python 依赖审计）", "skipped",
                "未检测到 Python 技术栈", available=False,
                hint=_INSTALL_HINTS["pip-audit"],
            )
        exe = _which("pip-audit")
        if not exe:
            return [], self._status(
                "pip-audit", "pip-audit（Python 依赖审计）", "skipped",
                "工具未安装，本次跳过依赖审计", available=False,
                hint=_INSTALL_HINTS["pip-audit"],
            )
        req = self.target / "requirements.txt"
        pyproject = self.target / "pyproject.toml"
        manifest: str
        if req.is_file():
            cmd: List[str] = [exe, "--format", "json", "-r", str(req)]
            manifest = "requirements.txt"
        elif pyproject.is_file() or (self.target / "Poetry.lock").is_file() \
                or (self.target / "uv.lock").is_file() or (self.target / "Pipfile").is_file():
            cmd = [exe, "--format", "json", "--path", str(self.target)]
            manifest = "pyproject.toml"
        else:
            return [], self._status(
                "pip-audit", "pip-audit（Python 依赖审计）", "skipped",
                "未找到 requirements.txt / pyproject.toml 等依赖清单",
                available=True,
            )
        ok, out, err, rc, err_kind = self._safe_run(cmd, "pip-audit")
        if not ok:
            return [], self._status(
                "pip-audit", "pip-audit（Python 依赖审计）", "error", err,
                available=True,
            )
        findings = self._parse_pip_audit(out, manifest)
        if findings and not out.strip().startswith("["):
            # 依赖清单为空等情况：pip-audit 输出空数组是正常的
            pass
        if not out.strip().lstrip("[").strip():
            detail = "已完成，未检出已知漏洞"
            return [], self._status(
                "pip-audit", "pip-audit（Python 依赖审计）", "ok", detail,
                available=True,
            )
        if not findings and not out.strip().startswith("["):
            detail = f"输出无法解析（退出码 {rc}）"
            if err.strip():
                detail += f"：{err.strip()[:160]}"
            return [], self._status(
                "pip-audit", "pip-audit（Python 依赖审计）", "error", detail,
                available=True,
            )
        detail = f"已完成，检出 {len(findings)} 个已知漏洞"
        return findings, self._status(
            "pip-audit", "pip-audit（Python 依赖审计）", "ok", detail,
            findings_count=len(findings), available=True,
        )

    def _parse_pip_audit(self, stdout: str, manifest: str) -> List[Finding]:
        try:
            data = json.loads(stdout)
        except (ValueError, TypeError):
            return []
        findings: List[Finding] = []
        for item in data if isinstance(data, list) else []:
            name = str(item.get("name") or "?")
            version = str(item.get("version") or "?")
            for vuln in (item.get("vulns") or []):
                vid = str(vuln.get("id") or "CVE-UNKNOWN")
                desc = str(vuln.get("description") or "").strip()
                fix = vuln.get("fix_versions")
                msg = f"{name}=={version} 存在已知漏洞 {vid}"
                if desc:
                    msg += f"：{desc[:200]}"
                if fix:
                    msg += f"（修复版本：{fix}）"
                f = Finding(
                    tool="pip-audit",
                    rule_id=f"pip-audit:{vid}",
                    severity=normalize_severity(vuln.get("severity") or "medium"),
                    path=manifest,
                    line=0,
                    message=msg,
                )
                findings.append(f)
        return findings

    # -------------------------------------------------------------- npm audit

    def run_npm_audit(self, js_detected: bool) -> Tuple[List[Finding], ToolStatus]:
        """Node 依赖审计。无 JS 栈或锁文件时跳过。"""
        if not js_detected:
            return [], self._status(
                "npm audit", "npm audit（Node 依赖审计）", "skipped",
                "未检测到 JavaScript/TypeScript 技术栈", available=False,
                hint=_INSTALL_HINTS["npm"],
            )
        exe = _which("npm")
        if not exe:
            return [], self._status(
                "npm audit", "npm audit（Node 依赖审计）", "skipped",
                "工具未安装，本次跳过依赖审计", available=False,
                hint=_INSTALL_HINTS["npm"],
            )
        if not (self.target / "package-lock.json").is_file() \
                and not (self.target / "npm-shrinkwrap.json").is_file():
            return [], self._status(
                "npm audit", "npm audit（Node 依赖审计）", "skipped",
                "未找到 package-lock.json（先执行 npm install 生成锁文件）",
                available=True,
            )
        ok, out, err, rc, err_kind = self._safe_run(
            [exe, "audit", "--json"], "npm", cwd=str(self.target)
        )
        if not ok:
            return [], self._status(
                "npm audit", "npm audit（Node 依赖审计）", "error", err,
                available=True,
            )
        findings = self._parse_npm_audit(out)
        if not out.strip().startswith("{"):
            detail = f"输出无法解析（退出码 {rc}）"
            if err.strip():
                detail += f"：{err.strip()[:160]}"
            return [], self._status(
                "npm audit", "npm audit（Node 依赖审计）", "error", detail,
                available=True,
            )
        detail = f"已完成，检出 {len(findings)} 项"
        return findings, self._status(
            "npm audit", "npm audit（Node 依赖审计）", "ok", detail,
            findings_count=len(findings), available=True,
        )

    def _parse_npm_audit(self, stdout: str) -> List[Finding]:
        try:
            data = json.loads(stdout)
        except (ValueError, TypeError):
            return []
        findings: List[Finding] = []
        vulns = (data.get("vulnerabilities") or {}) if isinstance(data, dict) else {}
        for pkg, info in vulns.items():
            if not isinstance(info, dict):
                continue
            titles: List[str] = []
            for via in (info.get("via") or [])[:3]:
                if isinstance(via, dict):
                    titles.append(str(via.get("title") or via.get("name") or ""))
                else:
                    titles.append(str(via))
            titles = [t for t in titles if t]
            msg = f"{pkg} 存在已知漏洞：{'；'.join(titles) if titles else '详见 npm audit 输出'}"
            f = Finding(
                tool="npm audit",
                rule_id=f"npm:{pkg}",
                severity=normalize_severity(info.get("severity")),
                path="package-lock.json",
                line=0,
                message=msg[:300],
            )
            findings.append(f)
        return findings

    # -------------------------------------------------------------- 编排入口

    def run_all(
        self, languages: Set[str], target_display: Optional[str] = None
    ) -> Tuple[List[Finding], List[ToolStatus], List[str]]:
        """按技术栈编排全部外部工具，返回 (findings, statuses, notes)。"""
        findings: List[Finding] = []
        statuses: List[ToolStatus] = []
        notes: List[str] = []

        f, st = self.run_gitleaks()
        findings += f
        statuses.append(st)

        rule_files = rule_files_for_languages(languages)
        f, st = self.run_semgrep(rule_files, target_display=target_display)
        findings += f
        statuses.append(st)
        if st.status == "skipped" and st.install_hint:
            notes.append(f"semgrep 未安装，已跳过 SAST。{st.install_hint}")

        langs_lower = {l.lower() for l in languages}
        f, st = self.run_pip_audit(any("python" in l for l in langs_lower))
        findings += f
        statuses.append(st)

        f, st = self.run_npm_audit(any("javascript" in l or "typescript" in l for l in langs_lower))
        findings += f
        statuses.append(st)

        return findings, statuses, notes
