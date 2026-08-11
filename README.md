<p align="center">
  <img src="https://raw.githubusercontent.com/AschoofAlpha/claude-shield/main/assets/social-preview.en.jpg" alt="Claude Shield — local-first privacy and proxy audit" width="100%">
</p>

<h1 align="center">Claude Shield</h1>

<p align="center"><strong>Local-first privacy and proxy-consistency audit for Claude Code and Agent Skills hosts.</strong></p>

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/AschoofAlpha/claude-shield/ci.yml?style=flat-square&label=CI" alt="CI">
  <img src="https://img.shields.io/badge/version-1.4.0-2DD4BF?style=flat-square" alt="v1.4.0">
  <img src="https://img.shields.io/badge/default-read--only-2DD4BF?style=flat-square" alt="Read-only by default">
  <img src="https://img.shields.io/badge/platform-Windows-4F7CFF?style=flat-square" alt="Windows">
  <img src="https://img.shields.io/badge/license-MIT-64748B?style=flat-square" alt="MIT License">
</p>

<p align="center"><a href="README.zh-CN.md">简体中文</a> · <a href="SKILL.md">Skill instructions</a> · <a href="LICENSE">MIT License</a></p>

> **How is your Claude account doing lately?**
>
> It's probably not bad luck — it's the road your traffic takes. You think everything goes through your proxy, but actually: DNS quietly falls back to your home broadband, a "backup tunnel" connects directly without the proxy, a small WebRTC backdoor lets websites see your real network address, or your proxy node randomly hops between countries at 3am.
>
> **Every one of these leaks tells the platform "something's off."** Accounts get flagged, challenged, even banned — often not because of what you say, but because of these details exposing you.
>
> Claude Shield is the tool that checks those details for you — **a read-only checkup that touches nothing**:
>
> - **Network egress**: where does your traffic actually leave from, and is anything bypassing the proxy?
> - **DNS resolution**: does a simple lookup secretly detour somewhere it shouldn't?
> - **Proxy setup**: are your nodes auto-hopping, are your rules silently broken?
> - **System state**: do your timezone, language, and privacy toggles contradict each other?
>
> When the checkup finishes, you get a **clear report** — every item labeled: **Must fix** (a real problem), **Optional consistency** (not a risk, but worth aligning), **Leave alone** (don't touch it).
>
> Then the decision is **entirely yours** — nothing changes without your explicit approval.
>
> And here's what this tool **won't do**:
>
> - It won't help you **impersonate someone else** (no fingerprint spoofing, no hiding automation)
> - It won't help you **fabricate identity** (no fake addresses, billing, or personal info)
> - It will never **guarantee** "this config means you'll never get banned" — anyone who promises that is lying to you.
>
> The "anti-ban" tools teach you to fool the platform. Claude Shield does one thing: **show you the truth**, and give you back the choice.
>
> **Audit first. Decide after.** Your account deserves one honest check.

## Install

```bash
pip install -U claude-shield
```

Requires **1.4.0+** for CLI `--out` / `--diff` / `--compact` / `--intended-mode` and parallel online probes.  
**1.3.3+** already includes the plain-language report, consistency score, and proxy-layer checks.  
Legacy package **`anti-claude-check`** is retired — use **`claude-shield`** only.


As an agent skill (Codex / Claude Code):

```powershell
git clone https://github.com/AschoofAlpha/claude-shield.git "$HOME/.codex/skills/claude-shield"
```

Invoke `$claude-shield` in Codex. For Claude Code, install the same folder as `~/.claude/skills/claude-shield` and invoke `/claude-shield`.

## CLI (1.4)

```bash
python -m claude_shield                 # full markdown report (offline)
python -m claude_shield --compact       # shorter markdown (score + must-fix / optional)
python -m claude_shield --json          # report_dict + summary as JSON
python -m claude_shield --out report.md
python -m claude_shield --json --out report.json
python -m claude_shield --diff previous.json
python -m claude_shield --online --timeout 5
python -m claude_shield --online --intended-region US
python -m claude_shield --intended-mode system_proxy   # or full_tunnel
python -m claude_shield --lang en
```

Online probes (egress, DNS observation, IP reputation, cross-site exits) stay **off** unless you pass `--online`. With `--online`, independent probes run in parallel (shared timeout).

`--out` writes the report to a file **and** still prints to stdout. `--diff` accepts a previous CLI `--json` payload or bare `report_dict` and appends a status-diff section (or a `diff` key in JSON mode). Default markdown is full; pass `--compact` for a short report (`--full` forces full if both are set).

Library defaults: `run_full_audit(include_recommendations=True)` returns `report_markdown` via `format_report`. Windows collector also reports Firefox WebRTC policy presence when detectable.

## What you get

- A full read-only Windows collector for proxy, DNS, IPv6, system, and documented Claude Code privacy settings, plus a limited POSIX environment summary.
- Clash Verge/Mihomo checks for rule mode, system proxy, service/TUN state, `strict-route`, fake-IP, DNS hijacking, LAN access, and the actual policy selection when its local controller is available.
- Recommendations split into **Must fix**, **Optional consistency**, and **Leave alone**.
- Optional, reversible privacy environment-variable remediation. No automatic DNS, route, firewall, VPN, or IPv6-adapter changes. Device-ID/cache/fingerprint items appear only as optional recommendations with explicit limits (local hygiene only; not server unban; no anti-detect stacks).
- Report plain-language **说明/meaning** on every check, a **configuration self-consistency** score (not anti-ban), and a soft footer listing what is **recommend-only never auto** (fingerprint, timezone-follow-node, env wipe, anti-ban score disguise, DNS/route/TUN).

The audit is local evidence, not a prediction of account approval or suspension.

Run `python -m claude_shield` for a live markdown report (`format_report`: evidence table + Must fix / Optional consistency / Leave alone). No staged demo screenshot is shipped.

## Read-only collection

Windows PowerShell 7:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\collect_windows_network.ps1
```

Windows PowerShell 5.1:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\collect_windows_network.ps1
```

macOS or Linux:

```bash
python ./scripts/collect_posix_network.py
```

Collector output can contain local identifiers. Keep raw output local and let the Skill redact it before sharing.

## Report

The Skill returns a compact evidence table (`signal`, `status`, `confidence`, `evidence`, `action`) followed by three short sections: **Must fix**, **Optional consistency**, and **Leave alone**. See `SKILL.md` for the exact report format and interpretation rules.

## Privacy opt-outs

Preview first:

```powershell
pwsh -NoProfile -File .\scripts\remediate_windows_network.ps1
```

After explicit approval, apply the documented Claude Code privacy environment variables:

```powershell
pwsh -NoProfile -File .\scripts\remediate_windows_network.ps1 -Apply
```

The script writes a backup and prints the exact rollback command. The broad non-essential-traffic opt-out can disable optional Claude Code features, so enable it only when that tradeoff is intended. On POSIX, `--apply` creates a private environment file and prints the `source` command; it does not edit shell profiles or network settings.

## Safety boundary

- No fingerprint spoofing, automation concealment, CAPTCHA bypass, or multi-account tooling.
- No fabricated identity, residence, billing, tax, or payment information.
- May recommend optional local device-id/cache hygiene or browser WebRTC hardening when artifacts are present; does not auto-delete IDs, does not spoof fingerprints, and cannot clear server-side marks or unban accounts.
- No claim that a configuration prevents account review or suspension.

Use current primary documentation for Claude Code privacy controls and rate limits. Treat third-party detector labels as opinions until live routing evidence corroborates them.

If this project finds a real leak or prevents an unnecessary destructive change, a GitHub star helps others discover it.
