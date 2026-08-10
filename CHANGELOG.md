# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-08-10

### Added
- CLI entry point: `python -m claude_shield [--online] [--json] [--timeout N] [--intended-region REGION]`.
  Markdown report by default; `--json` prints `report_dict` + `summary`. Online probes stay off unless `--online`.
- `claude_shield.report.format_report(checks)` / `group_checks(checks)` markdown formatter (evidence table + Must fix / Optional consistency / Leave alone).
- `run_full_audit(...).report_markdown` when the formatter is available.
- Windows collector: best-effort **Firefox** WebRTC policy detection (`Browsers.Firefox`) via Mozilla policy registry and `distribution/policies.json` (same shape as Chrome/Edge; no profile reads).
- Online probes: IP reputation observation and cross-site egress comparison (`intended_region`, `cross_site_urls` kwargs on `run_probes` / `run_full_audit`).

### Changed
- `run_full_audit(include_recommendations=True)` and `analyze_snapshot(include_recommendations=True)` default to **True**.
- Public exports include `format_report` / `group_checks` when the report module is present.
- Encrypted DNS upstream analysis accepts a single dict or a list of scheme objects.
- Version **1.3.0** across `pyproject.toml`, `__version__`, badges, and docs.

### Notes
- Package name remains **`claude-shield`**. Skill name remains **`claude-shield`**.
- Online reputation/cross-site probes contact public observers only when explicitly enabled; results are categorical and redacted.

## [1.2.2] - 2026-08-10

### Changed
- Agent Skill name/folder unified to **`claude-shield`** (was `anti-claude-check`).
- Invoke as `$claude-shield` (Codex) or `/claude-shield` (Claude Code).
- Remediation backup directory renamed to `~/.claude-shield` (old `~/.anti-claude-check` backups are left untouched).

## [1.2.1] - 2026-08-10

### Fixed
- Redaction no longer treats identifier slashes such as `Culture/UICulture/SystemLocale` as POSIX paths.
- Online DNS probe returns an honest observation (`unknown`) instead of a no-op skipped stub.

### Changed
- Split snapshot analysis into `claude_shield/analysis/*` (privacy / system / browser / mihomo).
- `run_full_audit()` now also returns a schema-validated `report` / `report_dict` (`AuditReport`).
- Public package exports: `run_full_audit`, `analyze_snapshot`, `AuditReport`, `Redactor`, etc.
- Egress probe comments cleaned up (behavior unchanged).

## [1.2.0] - 2026-08-10

### Fixed
- `run_probes(..., online=False)` is honored end-to-end. Offline audits no longer raise `unexpected keyword argument 'online'` and no longer emit a spurious `network.egress.probe_error`.
- Windows collector invocation now passes `-ExecutionPolicy Bypass`, matching the documented PowerShell entrypoints.
- Version metadata aligned: `pyproject.toml`, `claude_shield.__version__`, README badges, and this changelog all report **1.2.0**.

### Changed
- Online egress probes remain **off by default** (`run_full_audit(online=False)`). Live contact with Cloudflare Trace / ipify requires explicit `online=True` or a custom endpoint.
- Privacy analysis is more conservative: missing or unverified controls stay `unknown` instead of being treated as pass.
- Collector + redaction path favors minimal local identifiers and unified redaction before sharing.

### Notes
- Package name on PyPI is **`claude-shield`** (renamed from legacy `anti-claude-check`).
- Automated test suite: unit/smoke tests under `tests/` (currently 45+ cases).
- Install: `pip install claude-shield`

## [1.1.1] - 2026-08-03

### Fixed
- PyPI metadata: added `license = "MIT"` (previously showed as None).
- README image paths switched to absolute raw.githubusercontent URLs so the social preview and audit demo render on the PyPI project page (relative paths broke inside the wheel).

## [1.1.0] - 2026-08-03

### Added
- `run_full_audit()` combined entry point: collector + redaction + analysis + live egress probes in one call.
- Six new audit checks consuming previously unused collector fields:
  - `network.policy_group` — policy-group selection chain (no URL-test/fallback/load-balance auto selectors).
  - `network.dns_respect_rules` — `respect-rules` DNS behavior.
  - `network.dns_ipv6` — DNS IPv6 consistency.
  - `network.dns_encrypted` — encrypted upstream presence.
  - `network.dns_physical_resolver` — physical-ISP DNS resolvers on local adapters.
  - `network.tun_stack` — TUN stack (gvisor etc.).
- `claude_shield/analyze.py` analysis library with `run_legacy_collector()`, `analyze_snapshot()`, `summarize()`.
- GitHub Actions CI (Python 3.11/3.12 matrix, pytest + coverage).
- Bilingual pain-point README intro, social preview hero, and audit report demo image.

### Removed
- Interactive CLI (`cli.py`, `reporting.py`, launcher scripts, console entry points).
- Browser audit page (`assets/browser-audit.html`) and browser profile management (`browser/`, `browser_import.py`).
- Remediation transaction engine, credentials scanning, and `checks/`/`scanning/` modules.
- Browser scoring fields from `models.py` / `schema.py`.

### Changed
- Analysis logic moved from `cli.py` into the `claude_shield.analyze` library.
- Social preview redesigned around the account-flagging pain point; bilingual (EN/中文).
- Repository description and README intro rewritten in plain language.
- Version bumped to `1.1.0` stable.

## [1.1.0-beta.1] - 2026-07-27

### Added
- Safety hardening: redaction of local identifiers before sharing, explicit approval for state-changing actions.
- Identity restoration guidance (do not spoof, do not hide automation, do not fabricate identity).

## [1.0.0] - 2026-07-26

### Added
- Read-only Windows collector for proxy, DNS, IPv6, system, and Claude Code privacy settings.
- Clash Verge / Mihomo checks: rule mode, system proxy, service/TUN state, `strict-route`, fake-IP, DNS hijacking, LAN access, policy selection.
- Three-tier recommendations: **Must fix**, **Optional consistency**, **Leave alone**.
- Optional reversible privacy environment-variable remediation.
- POSIX collector (limited environment summary).
