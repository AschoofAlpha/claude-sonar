<p align="center">
  <img src="https://raw.githubusercontent.com/AschoofAlpha/claude-shield/main/assets/social-preview.jpg" alt="Claude Shield — 本地隐私与代理一致性审计" width="100%">
</p>

<h1 align="center">Claude Shield</h1>

<p align="center"><strong>面向 Codex、Claude Code 和 Agent Skills 宿主的本地隐私与代理一致性审计。</strong></p>

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/AschoofAlpha/claude-shield/ci.yml?style=flat-square&label=CI" alt="CI">
  <img src="https://img.shields.io/badge/version-1.3.2-2DD4BF?style=flat-square" alt="v1.3.2">
  <img src="https://img.shields.io/badge/default-read--only-2DD4BF?style=flat-square" alt="默认只读">
  <img src="https://img.shields.io/badge/platform-Windows-4F7CFF?style=flat-square" alt="Windows">
  <img src="https://img.shields.io/badge/license-MIT-64748B?style=flat-square" alt="MIT License">
</p>

<p align="center"><a href="README.md">English</a> · <a href="SKILL.md">Skill 指令</a> · <a href="LICENSE">MIT License</a></p>

> **你的 Claude 账号，最近还好吗？**
>
> 不是你的运气问题，多半是"出门的路"出了问题。你以为所有流量都走了代理，实际可能是：查东西时 DNS 偷偷绕回了你家宽带；某个"备用通道"没走代理直连了；网页甚至能通过一个叫 WebRTC 的小后门，看到你真实的上网地址；或者你的代理节点半夜自己乱跳，一会儿美国一会儿日本。
>
> **这些漏洞，每一个都在告诉平台"这个人不对劲"。** 账号被风控、被要求验证、甚至被封，很多时候不是内容的问题，是这些细节在暴露你。
>
> Claude Shield 就是帮你把这些细节查清楚的工具——**一次只读体检，不动你任何配置**：
>
> - **网络出口**：流量到底从哪出去，有没有没走代理的漏网之鱼
> - **DNS 解析**：查个网址，是不是偷偷经过了不该经过的地方
> - **代理设置**：节点是不是在自动乱跳，规则有没有失效
> - **系统状态**：时区、语言、隐私开关，有没有自相矛盾的地方
>
> 体检完，你会拿到一张清清楚楚的**报告**，每一项都标注：**必须处理**（这是真问题）、**可选一致性**（不影响安全但建议统一）、**保持不动**（别瞎折腾）。
>
> 然后，改不改、怎么改，**完全由你决定**——没有你的明确批准，它一个字都不会动。
>
> 最后说清楚这个工具**不做什么**：
>
> - 不帮你**伪装成另一个人**（不伪造指纹、不隐藏自动化）
> - 不帮你**编造身份**（不捏造地址、账单、个人信息）
> - 更不会**打包票**说"这样配就永远不会被封"——凡是这么承诺的，都是在骗你。
>
> 市面上的"防封神器"教你怎么骗过平台；Claude Shield 只做一件事：**让你看清真相**，把选择权还给你。
>
> **先体检，再决定。** 你的账号，值得一次诚实的检查。

## 快速开始

```bash
pip install claude-shield
```

作为 Agent Skill（Codex / Claude Code）：

```powershell
git clone https://github.com/AschoofAlpha/claude-shield.git "$HOME/.codex/skills/claude-shield"
```

在 Codex 中调用 `$claude-shield`。Claude Code 用户将同一目录安装到 `~/.claude/skills/claude-shield`，调用 `/claude-shield`。

## CLI（1.3）

```bash
python -m claude_shield                 # 默认 Markdown 报告（离线）
python -m claude_shield --json          # 输出 report_dict + summary
python -m claude_shield --online --timeout 5
python -m claude_shield --online --intended-region US
```

除非传入 `--online`，否则不会启用在线探测（出口、DNS、IP 声誉、跨站出口）。库默认 `run_full_audit(include_recommendations=True)`，并返回 `report_markdown`。Windows 采集器在可检测时也会报告 Firefox WebRTC 策略。

## 你会得到什么

- Windows 完整只读采集器：检查代理、DNS、IPv6、系统及 Claude Code 官方隐私设置；POSIX 仅提供有限的环境摘要。
- Clash Verge/Mihomo 检查：规则模式、系统代理、服务/TUN、`strict-route`、fake-IP、DNS 劫持、局域网访问，以及本地控制器可用时的实际策略选择。
- 建议明确分成 **必须处理**、**可选一致性** 和 **保持不动**。
- 可选且可回滚的隐私环境变量修复；不会自动修改 DNS、路由、防火墙、VPN、IPv6 网卡、设备 ID、缓存或浏览器指纹。

审计结果只是本地证据，不是账号通过审核或避免封禁的预测。

运行 `python -m claude_shield` 即可得到实时 Markdown 报告（`format_report`：证据表 + 必须处理 / 可选一致性 / 保持不动）。仓库不再附带伪造的演示截图。

## 只读采集

Windows PowerShell 7：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\collect_windows_network.ps1
```

Windows PowerShell 5.1：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\collect_windows_network.ps1
```

macOS 或 Linux：

```bash
python ./scripts/collect_posix_network.py
```

采集器原始输出可能含本地标识，请留在本机，由 Skill 脱敏后再分享。

## 报告

Skill 会返回一张紧凑的证据表（`signal`、`status`、`confidence`、`evidence`、`action`），后接三个短章节：**必须处理**、**可选一致性**、**保持不动**。完整报告格式与判定规则见 `SKILL.md`。

## 隐私开关

先预览：

```powershell
pwsh -NoProfile -File .\scripts\remediate_windows_network.ps1
```

经明确批准后，应用文档化的 Claude Code 隐私环境变量：

```powershell
pwsh -NoProfile -File .\scripts\remediate_windows_network.ps1 -Apply
```

脚本会写备份并打印精确的回滚命令。宽泛的非必要流量开关可能禁用 Claude Code 的某些可选功能，仅在明确接受该权衡时启用。POSIX 下 `--apply` 只创建私有环境文件并打印 `source` 命令，不修改 shell 配置或网络设置。

## 安全边界

- 不伪造指纹、不隐藏自动化、不绕过验证码，也不做多账号工具。
- 不编造身份、居住地、账单、税务或支付信息。
- 不自动删除设备 ID、遥测缓存，也不做全局网络修改。
- 不声称任何配置能防止账号审核或封禁。

Claude Code 隐私开关与限流规则以官方最新文档为准。第三方检测器标签只是观点，需有实时路由证据佐证。

如果这个项目帮你发现了一个真实泄漏、或避免了一次不必要的破坏性改动，一个 GitHub star 能让更多人找到它。
