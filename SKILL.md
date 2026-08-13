---
name: claude-shield
description: Audit a local Windows proxy and system setup, with limited macOS/Linux environment collection, for routing, DNS, IPv6, IP reputation, timezone, language, and documented Claude Code privacy controls. Use for Clash Verge/Mihomo or other proxy-leak diagnosis and minimal privacy hardening without fingerprint spoofing or platform-evasion guidance.
---

# Claude Shield

Audit privacy leaks, contradictory network signals, and documented Claude Code privacy controls without trying to defeat platform safeguards. Prefer stable, ordinary system behavior and the smallest defensible configuration change.

## Safety Boundary

- Work read-only by default. Ask before changing proxy, DNS, browser, or operating-system settings.
- Never elevate silently. Before an administrator-required change, show the exact scope, obtain approval, and ask the user to relaunch the controlling app or terminal as Administrator.
- Do not help spoof identity or browser fingerprints, bypass bot or fraud controls, evade regional restrictions, or support multi-account abuse.
- Do not recommend anti-detect browsers for risk-control evasion.
- Do not collect or expose cookies, passwords, subscription URLs, proxy credentials, payment details, or fabricated identity and billing data.
- Redact usernames, node names, IP addresses, and other sensitive identifiers before publishing reports.

## Triage External Tools

Do not install, execute, or copy a third-party repository merely because it appears in an audit. Inspect its stated purpose first, then classify it:

- Exclude [Camoufox](https://github.com/daijro/camoufox), [CloakBrowser](https://github.com/CloakHQ/cloakbrowser), and [browser-profiles](https://github.com/aitofy-dev/browser-profiles) from the workflow. Their documented features include anti-detect behavior, automation concealment, or fingerprint spoofing. Never use them to evade bot, fraud, or platform controls.
- If one of those tools is already present, report it as a high-impact diagnostic confounder. Do not uninstall it without approval.
- Treat [vargalott/mihomo](https://github.com/vargalott/mihomo) as configuration inspiration for TUN, `strict-route`, gvisor, and fake-IP concepts, not as a drop-in profile. It targets a specific dual-gateway censorship-circumvention setup; never copy its routes, ports, blanket blocks, placeholders, or credentials without mapping them to the local runtime.

Keep the bundled collector and live network checks as the primary workflow. Do not vendor these repositories or add them as dependencies.

## Host Compatibility

Use the directory containing this `SKILL.md` as `<skill-root>`. Resolve bundled files from that directory rather than from the current project or shell working directory.

- **Codex:** install the folder as `$CODEX_HOME/skills/claude-shield` or `~/.codex/skills/claude-shield`, then invoke `$claude-shield` or ask a matching audit question.
- **Claude Code:** install the folder as `~/.claude/skills/claude-shield` for personal use or `.claude/skills/claude-shield` for a project, then invoke `/claude-shield` or ask a matching question. Claude Code may resolve bundled files through `${CLAUDE_SKILL_DIR}`.
- **Other Agent Skills hosts:** preserve `SKILL.md`, `scripts/`, and their relative layout. Ignore `agents/openai.yaml` when the host does not use OpenAI interface metadata.
- **Other LLM agents:** load `SKILL.md` as instructions and run `<skill-root>/scripts/collect_windows_network.ps1`. On macOS/Linux, `scripts/collect_posix_network.py` supplies only OS, proxy-environment presence, and Claude Code privacy-control state; mark DNS, routing, IPv6, and proxy-client details as manual checks. If the agent cannot execute local commands, ask the user to run the collector and provide its JSON output.

On Windows hosts, prefer `pwsh`; fall back to `powershell.exe` 5.1. On macOS or Linux hosts, use the limited POSIX collector without claiming full network coverage.
After explicit approval, use the remediation scripts only for the documented Claude Code privacy environment variables. They must not reset device identifiers, delete caches, or change network adapters, DNS, routes, firewalls, VPNs, or browser fingerprints.

## Analysis Library

The bundled `claude_shield` package (skill name **`claude-shield`**) provides the standard analysis layer. Import it instead of hand-writing checks from the raw snapshot, so results stay consistent across runs:

```python
import sys
sys.path.insert(0, "<skill-root>")
from claude_shield.analyze import run_legacy_collector, analyze_snapshot, summarize, run_full_audit
from claude_shield.report import format_report
from claude_shield.redaction import Redactor

snapshot = run_legacy_collector()          # runs scripts/collect_windows_network.ps1
redactor = Redactor()
checks = analyze_snapshot(snapshot, redactor=redactor)  # recommendations included by default
redacted = redactor.scan_and_redact(snapshot)
summary = summarize(checks)
markdown = format_report(checks)           # evidence table + Must fix / Optional / Leave alone
```

For the default local-only audit (collector, redaction, analysis, markdown):

```python
from claude_shield.analyze import run_full_audit
result = run_full_audit(probe_timeout=5)   # include_recommendations=True, online=False
checks, summary, snapshot = result["checks"], result["summary"], result["snapshot"]
report_md = result["report_markdown"]      # same shape as format_report(checks)
```

CLI (never enables online unless `--online`):

```bash
python -m claude_shield
python -m claude_shield --json
python -m claude_shield --online --timeout 5 --intended-region US
```

Use online probes only after explicit approval:

```python
result = run_full_audit(
    probe_timeout=5,
    online=True,
    intended_region="US",          # optional ISO region hint for reputation soft-check
    # cross_site_urls=["https://..."],  # optional override list
)
```

- `run_legacy_collector()` raises `CollectorError` on failure; it never prints or exits.
- `analyze_snapshot()` returns `AuditCheck` objects; system-level checks run even when no Mihomo config is present. Default `include_recommendations=True`.
- `run_full_audit()` defaults: `include_recommendations=True`, `online=False`. Returns `checks`, `summary`, `snapshot`, `report`, `report_dict`, and `report_markdown`.
- Coverage includes privacy controls, service mode, system proxy, Teredo, classified IPv6 bindings and DNS resolvers, proxy environment-variable presence, Windows locale, browser WebRTC-policy presence (Chrome, Edge, **Firefox** best-effort), rule-mode routing, DNS configuration, TUN stack, and aggregate policy-selection types.
- `online=False` is the default. With `online=True`, probes may contact Cloudflare Trace / ipify (egress), a lightweight IP reputation observer, a small cross-site exit set, Google DoH (`o-o.myaddr.l.google.com`, DNS-vs-HTTP exit consistency), and api.anthropic.com via the local openssl binary (JA3/JA4 ClientHello capture). This discloses the public IP and request metadata to those providers; obtain approval and never treat a failed or skipped probe as a leak or pass. Reputation labels are vendor opinions; cross-site results compare redacted egress tokens only. The TLS fingerprint and DNS-exit checks are read-only observations — report them neutrally and never offer spoofing, fitting, or modification advice.
- `network.anthropic_baseurl` runs offline always: `ANTHROPIC_BASE_URL` unset / official / custom / blacklisted against a bundled 147-domain public relay-risk blacklist (intel from CACEB001/Claude-Shield, decoded base64+XOR-91; regenerate with `scripts/gen_baseurl_blacklist.py`). Treat a hit as risk intel, never as an accusation, and never help hide an endpoint.
- Browser collection reads installation presence and managed WebRTC policy settings only (Firefox: Mozilla policy registry + `distribution/policies.json`). It does not read browser profiles, exercise WebRTC, or prove runtime behavior.
- Feed the same `checks` into `format_report` or the Report Format section below. Do not re-derive the checks from raw JSON unless the library cannot run (then label every result `manual check required`).
- Package CLI: `python -m claude_shield`. Online stays off without `--online`.
  - `serve [--port N] [--open]` — read-only local web panel, 127.0.0.1 only. `/` renders the audit, `/api/report?online=0` returns the redacted report JSON, `/api/status`, `/api/badge`; the panel includes a browser-side observation block (WebRTC ICE candidates, timezone/language). Never add write endpoints, never bind non-loopback, never embed third-party scripts.
  - `repo PATH [--no-tools] [--baseline F] [--json] [--sarif F] [--out F]` — repository security scan (stack detection, semgrep/gitleaks/pip-audit/npm audit with graceful degradation, bundled trimmed Semgrep rules, 0–100 code-security score, fix suggestions, SARIF). No pentesting, no GitHub-issue filing.
  - `badge [--out PATH] [--from-report F]` — writes `shield-badge.json` for the shields.io dynamic badge. Regenerate after each audited change; the badge reflects the last written score, not a live audit.

## Audit Workflow

1. Establish the intended exit country or region and whether it is temporary or long-term.
2. On Windows, resolve `<skill-root>/scripts/collect_windows_network.ps1` and run it to collect a local snapshot. Pass `-ConfigDir` for a non-default Clash Verge installation and `-PolicyGroupPattern` for locally named service groups. On macOS/Linux, use the limited POSIX collector and keep unsupported areas manual. Do not dump complete proxy configuration or subscription files, and redact the snapshot before sharing it.
3. Review actual services, process and listener state, physical versus tunnel adapters, DNS configuration, proxy environment variables, Windows locale, and Mihomo policy groups.
4. For public IP reputation, unique-hostname DNS results, IPv4/IPv6, cross-site exits, and observed exit country, use an approved controlled probe or require manual verification. The collector snapshot does not replace external IP, DNS, or header tests.
5. Label every result `verified`, `inferred`, or `manual check required`. Never turn missing data into a pass.
6. Compare every signal with the intended exit rather than treating a detector's score as proof.
7. Classify findings as `must fix`, `optional consistency`, or `leave alone`.
8. Recommend the minimum local change, obtain approval, apply it, and run one verification pass.

## Adapt to the Local Computer

- Discover paths, profiles, services, adapters, and supported settings before recommending a change. Do not assume the default profile, port, interface name, or installation directory.
- Treat `Physical`, `TunnelOrVpn`, and `VirtualOrOther` adapter classifications as evidence, not authority. Ask for confirmation when a vendor-specific adapter is unclear.
- Never disable IPv6 on an adapter classified as a tunnel or VPN. Only propose changing an active physical adapter after confirming it is the real uplink and obtaining approval.
- Let the collector query Mihomo's local HTTP controller or Windows named pipe with a read-only `GET /proxies` request. If neither transport is reachable, report `ManualCheckRequired` and verify the selected policy group in Clash Verge. Do not infer a fixed node from the static YAML list.

## Required Coverage

Use the snapshot and live network tests together:

| Area | Local evidence | Completion rule |
| --- | --- | --- |
| Service mode | Matching Windows service state, Mihomo process, mixed-port listener | Service is running and the expected listener exists |
| Routing | Rule mode, system proxy, TUN, `strict-route`, stack, LAN access | Required values are verified in runtime-relevant configuration |
| IPv6 and Teredo | Teredo state plus classified active adapter bindings | No physical-uplink bypass; do not disable the Mihomo/tunnel adapter |
| DNS | `respect-rules`, fake-IP, `any:53`, DNS IPv6, local resolvers, encrypted upstream hosts | An approved unique-hostname live test shows no physical-ISP resolver; static settings alone are `unknown` |
| Browser WebRTC | Installed-browser and managed-policy observations | Settings are local evidence only; runtime behavior requires a controlled browser test or manual verification |
| Policy group | Rule reference, group type, HTTP or named-pipe controller selection chain | Intended service group is selected and the chain contains no URL-test, fallback, load-balance, smart, or other automatic selector; otherwise verify in the UI |
| Windows locale | Timezone, culture, UI culture, user language list, system locale | Explain mismatches; only change values that reflect genuine long-term use |
| Environment proxies | Presence of process, user, or machine `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, or `NO_PROXY` | Explain whether each is intentional; do not reveal its value |
| IP reputation | Country, ASN, provider type, proxy flags, abuse indicators, and blacklist claims from the supplied report | Separate confirmed routing facts from database opinions; corroborate severe claims when possible |
| Cross-site routing | Observed exit country, ASN, and IP grouping for each tested site | Protected sites follow the intended group; intentional direct routes are documented; physical-ISP exits are failures |
| Claude Code privacy | Three documented opt-outs and read-only supplemental-variable state | Report only presence/active state; change only the three documented opt-outs after approval |

## Claude Code Privacy Controls

Use only current, documented controls and distinguish metrics, error reports, feedback, and required model traffic:

- Treat `DISABLE_TELEMETRY=1` as the verified opt-out for operational metrics. Any other value is not a pass.
- Treat `DISABLE_ERROR_REPORTING=1` as the verified opt-out for operational error reports.
- Treat `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` as the broad documented opt-out for non-essential traffic.
- Report `CLAUDE_CODE_SKIP_PROMPT_HISTORY`, `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`, `OTEL_LOG_USER_PROMPTS`, `OTEL_LOG_TOOL_CONTENT`, `OTEL_LOG_TOOL_DETAILS`, and `OTEL_LOG_RAW_API_BODIES` as presence/active state only. Current-process state determines effective active status; user/machine scopes are configured-state context. Never expose values, and do not remediate these controls automatically.
- Treat an unset opt-out as a privacy preference, not a confirmed leak or account risk. The broad opt-out can disable optional Claude Code features and does not block required model traffic or the WebFetch domain-safety check; explain that tradeoff before setting it.
- Do not collect provider credentials. If the user supplies provider mode as context, do not infer account safety or eligibility from it.
- Do not delete `~/.claude.json` fields, telemetry caches, logs, or session data as an anti-review measure.
- Describe HTTP 429 as a rate-limit response unless current primary documentation proves a stronger conclusion. Never claim that a local setting prevents suspension.

## Interpret Results

Use these rules when reviewing IP, DNS, and routing reports:

| Signal | Pass | Investigate or fix |
| --- | --- | --- |
| DNS | Resolvers are reputable and geographically consistent with the exit | A physical-ISP resolver or a contradictory country appears |
| IPv6 | No IPv6 is exposed, or the visible IPv6 belongs to the same proxy egress | A physical-ISP IPv6 bypasses the proxy |
| Timezone | Reasonably consistent with long-term use and the intended region | A persistent, unexplained mismatch; treat as consistency, not a leak |
| Language | A plausible primary locale with ordinary secondary preferences | A surprising primary locale; do not treat extra languages as proof of abuse |
| TCP/IP and RTT | Record as low-confidence context | Do not chase inferred OS or latency labels unless corroborated by a real leak |
| IP reputation | Region and ASN are plausible; no corroborated severe abuse or blacklist signal | Conflicting proxy flags or severe abuse claims across multiple current sources |
| Cross-site routing | Sites follow their declared rule groups without exposing the physical ISP | A protected site exits through the physical ISP or an unintended country |

Do not call a long list of Google or Cloudflare anycast DNS servers a leak merely because the list is long. Do not call a proxy-owned IPv6 a local IPv6 leak when its geography and ASN align with the intended exit. Missing local or online evidence is `unknown`, never a pass.

## Review IP Reputation

- Record geolocation, ASN, organization, residential/datacenter/mobile classification, proxy or VPN labels, abuse scores, and blacklist claims from the supplied report.
- Treat country and ASN as routing evidence. Treat residential, proxy, risk, and abuse labels as vendor opinions that may be stale or contradictory.
- Corroborate a severe reputation claim with another current source when practical. Do not require every database to agree or require a residential label for a healthy route.
- Recommend contacting the provider or choosing another legitimate endpoint only when reputation causes a real reliability or access problem. Do not use reputation work to misrepresent identity, residence, billing, or eligibility.

## Review Cross-Site Routing

- Group tested sites by observed exit country, ASN, and IP without publishing the raw addresses.
- Compare each result with the user's actual Mihomo rule and policy group. A different exit can be correct for an intentionally direct or separately routed category.
- Mark a protected site using the physical ISP, an unintended country, or an unexpected automatic selector as `must fix`.
- Treat a fetch failure, CDN variation, or blocked probe as `unknown`, not as a leak. Re-test a small representative set after a rule change instead of forcing every site through one route.

## Recommend a Coherent Region

When several long-term signals conflict, offer one of these two consistency targets. Present it as optional operational consistency, not a way to evade platform review. Only change values that match the user's genuine usage; never alter identity, billing, tax, or payment information.

| Target | Exit and DNS | Timezone | System language |
| --- | --- | --- | --- |
| United States | Stable US exit; DNS routed through the tunnel and aligned with that exit | Match the exit's actual US time zone; the US has multiple time zones | `en-US`, retaining legitimate secondary languages |
| Japan | Stable Japan exit; DNS routed through the tunnel and aligned with Japan | `Asia/Tokyo` | `ja-JP`, retaining legitimate secondary languages |

For either target, prevent physical-network DNS or IPv6 bypasses. Do not spoof browser geolocation, remove system fonts, or rewrite unrelated OS settings. If the user frequently switches countries, recommend leaving timezone and language truthful rather than repeatedly changing them.

## Apply Approved Changes

Follow this sequence, incorporating lessons from prior Windows and Clash Verge remediation:

1. Capture the read-only snapshot and identify the single confirmed mismatch.
2. Prefer Clash Verge controls for mode, TUN, service mode, DNS, IPv6, and LAN access because the app can regenerate runtime YAML.
3. Show the proposed change, affected setting or file, expected effect, and rollback before editing.
4. Ask for explicit approval. If the change touches the service, TUN adapter, system DNS, IPv6 binding, Teredo, firewall, protected files, or system timezone, require the controlling app or terminal to be running as Administrator before continuing. Do not elevate for ordinary system-language changes.
5. Back up only a file that must be edited directly. Never copy or display `profiles.yaml`, subscription URLs, or the full configuration.
6. Preserve rule mode and system proxy when they already work. For the established full-tunnel baseline, verify TUN, service mode, `strict-route`, gvisor, fake-IP, `any:53`, `respect-rules`, LAN disabled, and the intended IPv6 behavior instead of rewriting the whole configuration.
7. When a physical IPv6 bypass is confirmed, disable only the verified physical uplink and Teredo; leave Mihomo and other required tunnel adapters intact.
8. Fully exit the target application before changing profile preferences. Reopen the same profile and verify preferences and runtime behavior.
9. Confirm the service-specific Mihomo group is referenced by rules and pinned to the intended manual selection. If runtime selection cannot be read, stop for a Clash Verge UI check.
10. Change one layer at a time, restart only the affected app or service, and verify runtime state rather than trusting a UI checkbox.
11. Re-run the local collector and one live network test pass. Roll back if a confirmed leak appears or routing breaks.

### Recommend-only — never auto-apply

These actions may appear in the report as **optional recommendations** only. Agents and scripts must **never** perform them automatically; the user must approve any manual change, and remediation scripts stay limited to documented privacy environment variables:

| Recommend-only (never auto) | Notes |
| --- | --- |
| Fingerprint spoof / anti-detect browsers | Policy-level WebRTC hardening advice only; no fabricated fingerprints |
| Timezone follow node | Timezone stays truthful consistency advice; never force-match exit country |
| Environment wipe / “launder” | No bulk clean of profiles, caches, or identity to look “fresh” |
| Anti-ban / stealth score disguise | Score is **configuration self-consistency** only — not unban or country look-alike |
| Auto network: DNS · route · TUN · IPv6 · system proxy | Report may suggest; user applies via their proxy app after approval |

**Remediation scripts** (`remediate_*.ps1` / `remediate_posix_network.py`) remain **privacy env vars only**. They do **not** reset device IDs, clear caches, spoof fingerprints, follow timezone to the node, or change DNS/routes/TUN/IPv6.

Remember that Clash Verge UI state and generated Mihomo runtime configuration may live in different files. A listener can be owned by `verge-mihomo`; process-name checks should include it. After changing system language order, verify the running locale. A matching proxy-provided IPv6 is not evidence that the local IPv6 binding was re-enabled.

## Mihomo Baseline for Full-Tunnel Leak Prevention

When the goal is a Windows full-tunnel setup, check this baseline without assuming every environment must be identical:

- Use rule mode with system proxy, service mode, and TUN enabled.
- Enable `strict-route`; use the stable TUN stack already proven on the machine, commonly `gvisor`.
- Enable Mihomo DNS with `fake-ip` and `any:53` hijacking.
- Keep local IPv6 and Teredo disabled when the selected route does not deliberately support them.
- Disable LAN access unless it is explicitly required.
- Pin sensitive service traffic to a deliberate, stable policy group instead of automatic node selection.

Distinguish local interface settings from public egress behavior. A local IPv6-disabled setting can coexist with a proxy-provided IPv6 at the remote endpoint.

## Generic Baseline for Non-Clash Proxies

If the user employs a proxy core other than Mihomo (e.g., Xray, Sing-Box native, Surge, Quantumult X):
- Do not attempt to read or write Clash-specific YAML configurations.
- Verify the proxy client's documented routing and DNS behavior, then confirm it with live tests. Do not infer a leak from system-proxy mode alone or prescribe an extension without evidence.
- Change DNS, IPv6, or TUN settings only after a live test identifies the bypassing layer.
- **Use OS-Level Probes to Verify Isolation (macOS Example)**: Since you cannot read their proprietary config files, verify the actual OS network state:
  - Run `ifconfig | grep -E "utun|tun"` to ensure a virtual network interface is active.
  - Run `scutil --dns` to record resolver order and fake-IP entries. Static resolver presence alone does not prove a leak; use an approved unique-hostname test for the active path.
  - Run `netstat -nr -f inet | grep -e "default" -e "0/1" -e "128.0/1"` to verify if the default route or a fake-ip route points to the `utun` interface.
- Use the remediation scripts only for documented privacy environment variables. Handle proxy-client and IPv6 changes manually, one verified setting at a time, after explicit approval.

## Report Format

When the user supplies a collector snapshot (or an agent runs the collector), parse its redacted evidence and display the report before the evidence table. Treat every score as a transparent local heuristic, not independent proof. Explain each flagged item in the context of the collector and live tests; never convert an unknown public exit into a confirmed leak without comparing it with the intended exit.

**Prefer the library formatter** so jargon is explained consistently:

```python
from claude_shield import run_full_audit, format_report
result = run_full_audit(online=False, lang="zh")   # or lang="en"
print(result["report_markdown"])
# equivalent: format_report(result["checks"], summary=result["summary"], lang="zh")
```

Present the result **as markdown tables in the chat** (do not dump a long prose essay). Prefer `result["report_markdown"]` / `format_report(..., lang="zh")`.

The library markdown includes:
- intro noting local evidence only + **配置自洽分 / consistency score** (not anti-ban)
- **配置自洽分** / **Consistency score** table (0–100 configuration self-consistency)
- **全部结果** table with columns: 检查项 / 状态 / **说明** / 详情 / 分组 / 建议  
  (English: check / status / **meaning** / detail / group / recommendation)
- section tables: 必须处理 / 可选一致性 / 保持不动 — each row still has a **说明/meaning** plain-language line
- **名词解释** glossary table
- footer: what the tool will **not** auto-do (fingerprint, timezone-follow-node, env wipe, anti-ban score disguise, DNS/route/TUN)

Every listed check must keep a clear 说明/meaning column (from `plain_check`). Ordinary explanations go there — never a separate label like `plain:`.

If you must hand-build the reply, still use tables and put jargon explanations in a 说明/meaning column. Sections:

1. 必须处理 — confirmed leaks or route failures
2. 可选一致性 — non-leak mismatches
3. 保持不动 — healthy or no action

State uncertainty explicitly. Reputation scores, TCP/IP inference, and RTT are not standalone proof of proxy use or abuse. Never promise that a configuration will prevent account review, suspension, or platform detection. Do not present the numeric score as an anti-ban or “looks like country X” score.

## Verification

After explicit approval, re-run controlled public tests after a node, network, or configuration change. Use a fresh unique hostname for DNS so cached answers do not hide the active resolver path. A healthy result is internally consistent and free of confirmed bypasses; it does not need every heuristic detector to show green. Do not mark the audit complete while any required item is `unknown` or `ManualCheckRequired`.


## Local identity / cache / fingerprint recommendations

When local Claude paths or unrestricted WebRTC posture are observed, the report may recommend **optional** local device-id reset, telemetry-cache hygiene, or browser WebRTC hardening. These never auto-run, never spoof fingerprints, and **cannot** clear server-side device marks or unban accounts.
