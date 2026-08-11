# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.1] - 2026-08-11

### Added
- Personalized guidance: auto-detect the active proxy client (Clash Verge / Mihomo / v2rayN / Xray / sing-box / Hiddify / NekoBox / Hysteria / Netch, …) and show app-specific manual tips.
- Report section "个性化（检测到的代理）": primary client, engine, confidence, plus manual action list — timezone align to exit/node, local hygiene, DNS/route/TUN/IPv6/system proxy — all recommend-only, never auto-applied.
- New check `client.profile` (informational).
- Windows collector: `PrimaryProxyProcesses` (name + label, no paths); other-client list now excludes the primary client to avoid false "extra client" noise.

### Changed
- Footer renamed to "本工具如何协助你改配置 / How this tool helps you change settings": clarifies it *can* suggest manual steps (timezone follow node, hygiene, DNS/route/TUN/IPv6/system proxy) but will never auto-apply them.
- Version 1.4.1 across metadata/badges/docs.

## [1.4.0] - 2026-08-11


### Added
- CLI flags: `--out PATH` (write report file and still print to stdout), `--diff PATH` (compare against a previous JSON `report_dict` / CLI `--json` payload), `--intended-mode {system_proxy,full_tunnel}`, `--compact` (short markdown), `--full` (explicit full report; overrides `--compact`).
- `claude_shield.diff`: `diff_audits` / `diff_reports`, `format_diff_markdown`, `load_checks_from_report_dict` / `load_previous_report` for check-id status diffs.
- Online probes: independent DNS / reputation / cross-site / dual-stack / stability probes run in a thread pool (ordered merge; sequential fallback). Offline path unchanged.
- `run_full_audit(..., intended_mode=None, compact=False)` and `analyze_snapshot(..., intended_mode=None)` coordination stubs; `format_report(..., compact=False)`.

### Changed
- Version **1.4.0** across package metadata, badges, and docs.
- CLI forwards `--lang` into `run_full_audit` and always re-renders markdown via `format_report`.

## [1.3.3] - 2026-08-11

### Added
- Offline checks: `network.proxy_layers`, `network.proxy_autoconfig`, smarter `network.env_proxy`, `consistency.geo_stack`.
- Windows collector fields: `WinHttpProxy`, `ProxyAutoConfig` (boolean flags only), broader other-proxy process names.
- Online probes: multi-DNS observation classes, dual-stack egress, `network.egress.stability`, `browser.webrtc.guidance` (manual test guidance only).
- Report: plain-language **说明/meaning** column, **配置自洽分 / consistency score** (0–100), glossary, footer of actions that are **recommend-only never auto**.
- Optional recommendations only for local device-id hygiene, cache hygiene, and browser WebRTC posture (never auto-applied; not unban).

### Changed
- Report intro wording: neutral read-only + consistency score (no ban-prediction framing in the header).
- PAC/WPAD: missing AutoDetect registry value + no PAC URL treated as pass (common on Windows).
- Fingerprint spoof, timezone-follow-node, environment wipe, anti-ban score disguise, and automatic DNS/route/TUN/IPv6/system-proxy changes remain **recommendations only** — remediation scripts still only touch documented Claude Code privacy env vars.

### Notes — version history clarity
- **PyPI package name remains `claude-shield`.** Legacy **`anti-claude-check`** is retired/removed; install only `claude-shield`.
- **About 1.3.2 “dual content”:**
  - The **first** `1.3.2` upload to PyPI (and the matching early git tag period) mainly **removed** the fake `audit-demo` screenshot.
  - **After** that wheel was published, more features landed on git `main` while the version string stayed `1.3.2` (no second PyPI build for the same number). Those later commits are **not** guaranteed inside the original PyPI `1.3.2` files.
  - **`1.3.3` is the first PyPI release that packages the full post-1.3.2 mainline** (proxy-layer checks, plain report, consistency score, online probe extensions, recommend-only boundaries). Prefer `pip install -U claude-shield` (≥1.3.3) or install from git `main`.

## [1.3.2] - 2026-08-10

### Removed
- Fake staged audit demo image `assets/audit-demo.jpg` and README embeds. Use `python -m claude_shield` / `format_report` for real output.

### Notes
- **PyPI `1.3.2` wheel = this removal-focused release.** Later git commits that kept the label `1.3.2` without a new PyPI build are documented under **1.3.3** above. Do not assume `pip install claude-shield==1.3.2` includes those later features.

## [1.3.1] - 2026-08-10

### Changed
- POSIX collector and remediation rewritten in **Python** (`scripts/collect_posix_network.py` / `scripts/remediate_posix_network.py`); bash scripts removed.
- Removed unused marketing HTML sources under `assets/` (README continues to use JPG previews only). Language breakdown is now Python + PowerShell (+ tiny docs).

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
