# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 修正
- HTTP 探测 User-Agent 从 `Claude-Shield` 改为 `Claude-Sonar`
- 中文 README 补上配置自洽分徽章；去掉易混淆的「CLI 1.4」标题
- CHANGELOG `[1.0.2]` 错字；Issue 模板版本占位改为 1.0.3
- 「保持不动」里的 `unknown` 状态改标「证据不足，不是问题」；名词解释同步。不把 unknown 改成 pass
- SKILL：只有「必须处理」仍 unknown 才算体检未完成；保持不动里的 unknown 不算没做完
- 新增 `static/demo.html`：零后端、零第三方脚本的即开即用浏览器观测页（WebRTC 候选、时区/语言、canvas 只读哈希、出口 IP 第三方标签），不伪装、不改设置；README 与打包清单同步
- demo 页 v2：Client Hints、简繁字体渲染、国旗 emoji 渲染、AI 平台连通性（no-cors 仅测可达）、深浅主题、复制链接、本地历史；GitHub Pages 部署工作流
- 新增在线探测 `network.ai_connectivity`：多平台 AI 主页可达性（沿代理路径，仅连通性观察，失败算 unknown 不算泄漏）

## [1.0.3] - 2026-08-19

版本号统一升级，将之前本地/远程的 1.0.1 进度收口到 1.0.3（跳过 1.0.2）。

### 修正
- 中文报告剩余英文句子全部译完：路由/TUN/信誉查询/双栈 IPv4 等
- 373 项测试全绿

## [1.0.2] - 未发布

跳号，未单独发布。

## [1.0.1] - 2026-08-19

实机体检后的一轮报告与探测修正（不改变检测边界）：

### 报告
- 聊天默认只贴三分组（必须处理/可选一致性/保持不动）；「全部结果」改为 `--full` / `include_all_results=True` 选入
- 6 项补充隐私（OTEL×4、本地历史、子进程擦除）折叠为一行「补充隐私项」；4 项浏览器 WebRTC 折叠为一行
- `lang=zh` 补齐中文词条（跨站、PAC、双栈、稳定性等不再漏英文句子）

### 误判修正
- 未设置 `ANTHROPIC_BASE_URL` = 官方端点，不再标 `[not_configured]`、不再扣分
- 本机 Claude 目录/遥测缓存存在 = 用过即有，归入「保持不动」，不扣分
- en-* + zh-Hans/zh-CN 双语 locale = 正常，不再警告
- 成功抓到 TLS 指纹 = 观察成功（通过），不再标未知

### 探测
- 未声明模式时自动推断 `intended_mode`（系统代理回环+TUN关 → system_proxy；TUN开 → full_tunnel）
- 跨站路由复用同一次运行的出口 token（共享同一 Redactor，避免脱敏盐不一致误报）
- fake-IP + 53 劫持通过时跳过 DoH 对照（dns.google 常被代理拦截）
- 环境变量代理已通过时，不再劝 CLI 用户开全局+TUN

## [1.0.0] - 2026-08-14

这是一个全新开始。项目从 `claude-shield` 更名为 `claude-sonar`，正式发布 1.0.0。

### 核心功能
- **只读审计 Skill + Python 库 + CLI**：检测 Claude Code / Codex 等 Agent 宿主的本地隐私与代理一致性，不动任何配置
- **本地面板**（`serve`）：零依赖、仅 127.0.0.1、自动审计 + 渐变进度条分数区 + 出口概览卡片 + DNS/WebRTC/TLS 独立小卡 + pill 式摘要
- **代码仓库安全扫描**（`repo`）：栈检测 + Semgrep/gitleaks/依赖审计 + 过期检测 + 0-100 评分 + SARIF 导出
- **动态徽章**（`badge`）：sonar-badge.json + shields.io

### 检测维度
- Claude Code 三隐私变量 + 补充隐私项
- 代理客户端识别（Clash Verge/v2rayN/sing-box 等）+ 个性化手动建议
- 代理核心配置（规则模式、TUN、strict-route、fake-IP、DNS 劫持、DoH）
- 防泄漏面（Teredo、IPv6 绑定、PAC/WPAD）
- 在线探测（可选）：出口 IP 信誉、跨站路由一致性、出口稳定性
- BASE_URL 黑名单审计（147 域名）+ AI 实验室关键词比对 + TCP 拨测
- DNS 出口一致性（DoH vs HTTP）+ JA3/JA4 TLS 指纹（openssl 抓包，只读）
- 时区 / 语言 / 区域一致性
- 浏览器 WebRTC 策略 + 浏览器端 ICE 候选实测（面板内）
- socks5h 远程 DNS 建议 / SSH 隧道手动指引（仅建议，不代改）

### 产品边界
- 只检测，不伪装、不伪造指纹、不自动改网络、不自动改时区
- 报告五列表格直贴对话框（检查项/状态/严重度/说明/建议）
- 行排序：通过 → 警告 → 未知
- 全中文面板 payload

### Changed from previous project
- 项目名 `claude-shield` → `claude-sonar`
- Python 包名 `claude_shield` → `claude_sonar`
- 正式发布 1.0.0
- CHANGELOG 历史已清除