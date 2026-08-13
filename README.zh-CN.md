<p align="center">
  <img src="https://raw.githubusercontent.com/AschoofAlpha/claude-shield/main/assets/social-preview.jpg" alt="Claude Shield — 本地隐私与代理一致性审计" width="100%">
</p>

<h1 align="center">Claude Shield</h1>

<p align="center"><strong>面向 Codex、Claude Code 和 Agent Skills 宿主的本地隐私与代理一致性审计。</strong></p>

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/AschoofAlpha/claude-shield/ci.yml?style=flat-square&label=CI" alt="CI">
  <img src="https://img.shields.io/badge/version-1.4.9-2DD4BF?style=flat-square" alt="v1.4.9">
  <img src="https://img.shields.io/badge/default-read--only-2DD4BF?style=flat-square" alt="默认只读">
  <img src="https://img.shields.io/badge/platform-Windows-4F7CFF?style=flat-square" alt="Windows">
  <img src="https://img.shields.io/badge/license-MIT-64748B?style=flat-square" alt="MIT License">
</p>

<p align="center"><a href="README.md">English</a> · <a href="SKILL.md">Skill 指令</a> · <a href="LICENSE">MIT License</a></p>

> **你的 Claude 账号，最近还好吗？**
>
> 如果你在国内用 Claude，下面这些场景你多半不陌生：
>
> - 刚充的会员还没用几天，账号突然登不上去了
> - 攒了好几个月的对话、项目上下文，一夜之间全跟着账号没了
> - 申诉邮件发出去，石沉大海
> - 换个邮箱重新注册，新号还没捂热，又被封了
> - 明明只是正常提问，却总被当成"高风险用户"
>
> 这不是你的运气问题，多半是"出门的路"出了问题。你以为所有流量都走了代理，实际上：
>
> - 查个网址，你的电脑先偷偷去问了自家宽带的 DNS
> - 某个"备用通道"没走代理，直接连出去了
> - 网页还能通过浏览器自带的一个小功能（WebRTC），瞄到你的真实上网地址
> - 代理节点半夜自己换国家，一会儿美国一会儿日本
>
> **这些细节，每一个都在告诉平台"这个人不对劲"。** 账号被风控、被要求验证、甚至被封，很多时候不是内容的问题，是这些细节在暴露你。更麻烦的是：这些隐患平时毫无感觉，等你看到封号页面的时候，一切都晚了。
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
pip install -U claude-shield
```

CLI `--out` / `--diff` / `--compact` / `--intended-mode` 与并行在线探测请使用 **1.4.0+**。  
说明列、配置自洽分、代理分层检查等报告能力自 **1.3.3+** 起已具备。  
旧包名 **`anti-claude-check`** 已停用，请只安装 **`claude-shield`**。


作为 Agent Skill（Codex / Claude Code）：

```powershell
git clone https://github.com/AschoofAlpha/claude-shield.git "$HOME/.codex/skills/claude-shield"
```

在 Codex 中调用 `$claude-shield`。Claude Code 用户将同一目录安装到 `~/.claude/skills/claude-shield`，调用 `/claude-shield`。

## CLI（1.4）

```bash
python -m claude_shield                 # 完整 Markdown 报告（离线）
python -m claude_shield --compact       # 精简报告（分数 + 必须处理 / 可选一致性）
python -m claude_shield --json          # 输出 report_dict + summary
python -m claude_shield --out report.md
python -m claude_shield --json --out report.json
python -m claude_shield --diff previous.json
python -m claude_shield --online --timeout 5
python -m claude_shield --online --intended-region US
python -m claude_shield --intended-mode system_proxy   # 或 full_tunnel
python -m claude_shield --lang en
python -m claude_shield serve --port 8765  # 只读本地网页面板（仅 127.0.0.1）
python -m claude_shield repo ./my-project  # 代码仓库安全扫描（SAST/密钥/依赖）
python -m claude_shield badge              # 从审计结果生成 shield-badge.json
```

子命令（同一入口 `python -m claude_shield`）：

- **`serve [--port N] [--open]`** — 零依赖本地网页面板，**仅绑定 127.0.0.1**。`/` 渲染审计结果（分数、必须处理/可选一致性/保持不动分组）；`/api/report?online=0` 返回脱敏后的报告 JSON（在线探测默认关闭，需手动打开）；附带浏览器端观察区（WebRTC ICE 候选、本地时区/语言）。只读：POST 返回 405、路径穿越 404、仅接受回环 Host 头。
- **`repo PATH [--no-tools] [--baseline F] [--json] [--sarif F] [--out F]`** — 代码仓库安全扫描：技术栈识别、semgrep / gitleaks / pip-audit / npm audit / 过期检测（npm outdated、pip list --outdated）编排（工具缺失自动跳过并注明）、内置精简 Semgrep 规则（MIT 来源已注明）、0–100 加权代码安全分、修复建议、基线对比、SARIF 2.1.0 导出。不含渗透测试、不自动建 GitHub issue。
- **`badge [--out PATH] [--from-report F]`** — 写入 `shield-badge.json`（分数+颜色），供下方 shields.io 动态徽章使用；`--from-report` 可复用上次 `--json` 报告、无需重新审计。

除非传入 `--online`，否则不会启用在线探测（出口、DNS、IP 声誉、跨站出口、**DNS 与 HTTP 出口一致性**、**JA3/JA4 TLS 指纹**）。启用 `--online` 时，独立探测会并行执行（共享超时）。`ANTHROPIC_BASE_URL` 审计（官方端点 vs 内置公开风控黑名单情报）始终离线运行。

`--out` 写入文件的同时仍打印到 stdout。`--diff` 接受上次 CLI `--json` 输出或裸 `report_dict`，在 Markdown 末尾追加对比段（JSON 模式增加 `diff` 字段）。默认完整报告；`--compact` 输出精简版（若与 `--full` 同时出现，以 `--full` 为准）。

库默认 `run_full_audit(include_recommendations=True)`，并返回 `report_markdown`。Windows 采集器在可检测时也会报告 Firefox WebRTC 策略。

## 你会得到什么

| 层 | 检查 |
| --- | --- |
| Claude 隐私 | 3 个主开关 + 6 项补充变量 + 本地残留 |
| 代理 | 系统代理 / WinHTTP / 环境变量 / PAC / 其它客户端冲突 |
| DNS | fake-IP、53 劫持、DoH、物理网卡残留、浏览器 Secure DNS |
| 路由 | TUN、默认路由、Teredo、IPv6 旁路 |
| 在线（可选） | DNS 与 HTTP 出口一致性（DoH）、JA3/JA4 TLS 客户端指纹（openssl 抓包） |
| 始终运行 | `ANTHROPIC_BASE_URL` 审计（内置公开中转风险黑名单比对） |
| 本地面板 | `serve` — 127.0.0.1 只读面板 + 浏览器端 WebRTC/时区观察 |
| 仓库扫描 | `repo` — SAST / 密钥 / 依赖审计，0–100 代码安全分 |
| 徽章 | `badge` — `shield-badge.json` 驱动 shields.io 动态徽章 |
| 一致性 | 时区 × 语言 ×（在线）出口地区 |
| 个性化 | 自动识别你的梯子（Clash Verge / v2rayN / sing-box / …）并按软件给手动步骤 |

结果分为 **必须处理**、**可选一致性**、**保持不动**；每项都有白话 **说明** 列，报告含 **配置自洽分**（不是防封分），页脚标明「只建议、不自动」：改指纹 / 时区跟随节点 / 清环境洗白 / 防封评分伪装 / 改 DNS·路由·TUN。

仅提供可选且可回滚的隐私环境变量修复；不会自动修改 DNS、路由、防火墙、VPN、IPv6 网卡、设备 ID、缓存或浏览器指纹。

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

## 手动网络替代方案（仅建议，绝不代改）

当审计提示 DNS/HTTP 出口不一致时，有两个标准工具方案值得了解——均为手动、可逆，本工具绝不会替你执行：

- **socks5h 远程解析** — 把 Claude Code 的代理指向 `socks5h://127.0.0.1:<端口>` 形式（而非 `socks5://` 或 `http://`）。`h` 让域名解析在代理端完成，消除大部分本地 DNS 绕过路径。
- **SSH 动态转发** — 在保持打开的终端里运行 `ssh -N -D 1080 user@你的VPS`（Windows 自带 OpenSSH），再把工具指向 `socks5h://127.0.0.1:1080`，即可用自有 VPS 做固定出口、无需本地代理客户端。

这是常规代理用法，不是伪装；审计保持只读，只做建议。

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

报告在发现本地 Claude 目录/缓存或浏览器 WebRTC 策略偏松时，可以**建议**是否做本地 device-ID 重置、清理遥测缓存、加强浏览器隐私/WebRTC 设置；这些建议默认不自动执行，**不能**清除服务端设备标记，也**不**推荐反检测浏览器或指纹伪装。

## 安全边界

- 不伪造指纹、不隐藏自动化、不绕过验证码，也不做多账号工具。
- 不编造身份、居住地、账单、税务或支付信息。
- 不自动删除设备 ID、遥测缓存，也不做全局网络修改。
- 不声称任何配置能防止账号审核或封禁。

Claude Code 隐私开关与限流规则以官方最新文档为准。第三方检测器标签只是观点，需有实时路由证据佐证。

如果这个项目帮你发现了一个真实泄漏、或避免了一次不必要的破坏性改动，一个 GitHub star 能让更多人找到它。
