"""Dynamic sonar badge helpers for Claude Sonar.

Writes ``sonar-badge.json`` in the shields.io ``dynamic/json`` schema and
builds a shields.io badge URL that reads the score straight from that file
once it is pushed to a public repository. Standard library only.
"""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Any, Optional

DEFAULT_LABEL = "配置自洽分"
DEFAULT_REPO = "https://github.com/AschoofAlpha/claude-sonar"


def badge_color(score) -> str:
    """Map a 0-100 score to a shields.io color name (green / yellow / red).

    Bands follow the report grade system: A (>=90) green, B/C (>=60)
    yellow, D (<60) red.
    """
    score = int(score)
    if score >= 90:
        return "brightgreen"
    if score >= 60:
        return "yellow"
    return "red"


def make_badge(score, out_path) -> dict:
    """Write the shields.io dynamic/json badge payload for ``score``.

    Returns the written payload dict. Creates parent directories as needed.
    """
    payload = {
        "schemaVersion": 1,
        "label": DEFAULT_LABEL,
        "message": f"{int(score)}/100",
        "color": badge_color(score),
    }
    target = Path(out_path)
    if target.parent and str(target.parent) not in ("", "."):
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return payload


def score_from_result(result) -> Optional[int]:
    """Extract the 0-100 self-consistency score from a ``run_full_audit`` result.

    Returns ``None`` when the result has no checks or scoring fails.
    """
    checks = (result or {}).get("checks") or []
    if not checks:
        return None
    try:
        from .report import score_checks

        return int(score_checks(checks).get("score", 0))
    except Exception:
        return None


def make_badge_from_result(result, out_path) -> dict:
    """Update ``sonar-badge.json`` from the latest audit result."""
    score = score_from_result(result)
    if score is None:
        raise ValueError("audit result contains no checks; cannot build badge")
    return make_badge(score, out_path)


def project_root() -> Path:
    """Best-effort project root (source checkout, else the current directory)."""
    root = Path(__file__).resolve().parent.parent
    if (root / "static" / "panel.html").exists() or (root / "pyproject.toml").exists():
        return root
    return Path.cwd()


def default_badge_path() -> Path:
    """Where ``sonar-badge.json`` lives (project root)."""
    return project_root() / "sonar-badge.json"


def default_shield_json_url() -> str:
    """GitHub raw URL for the badge JSON, resolved from package metadata."""
    repo: Optional[str] = None
    try:
        from importlib.metadata import metadata

        for entry in metadata("claude-sonar").get_all("Project-URL") or []:
            if entry.startswith("Repository,"):
                repo = entry.split(",", 1)[1].strip()
                break
    except Exception:  # pragma: no cover - metadata lookup is best-effort
        repo = None
    repo = (repo or DEFAULT_REPO).rstrip("/")
    return f"{repo}/raw/main/sonar-badge.json"


def make_badge_markdown(shield_json_url: Optional[str] = None, label: Optional[str] = None) -> str:
    """Return the shields.io dynamic/json badge URL string.

    The badge reads ``$.message`` (``88/100``) from ``sonar-badge.json``
    served over a public raw URL, e.g. ``https://github.com/<user>/<repo>/raw/main/sonar-badge.json``.
    """
    json_url = shield_json_url or default_shield_json_url()
    label_text = label or DEFAULT_LABEL
    shields_url = (
        "https://img.shields.io/badge/dynamic/json?url="
        + urllib.parse.quote(json_url, safe="")
        + "&query=$.message&label="
        + urllib.parse.quote(label_text, safe="")
    )
    return shields_url


def make_badge_md_link(shield_json_url: Optional[str] = None, label: Optional[str] = None) -> str:
    """Convenience: the badge URL wrapped as a markdown image link."""
    shields_url = make_badge_markdown(shield_json_url=shield_json_url, label=label)
    return f"[![claude-sonar]({shields_url})]({shields_url})"


__all__ = [
    "badge_color",
    "make_badge",
    "make_badge_from_result",
    "make_badge_markdown",
    "make_badge_md_link",
    "score_from_result",
    "default_badge_path",
    "default_shield_json_url",
    "DEFAULT_LABEL",
]
