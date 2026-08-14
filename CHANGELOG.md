# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7] - 2026-08-14

这是一个全新开始。项目从 `claude-shield` 更名为 `claude-sonar`，版本号重置为 0.7。

### 核心功能
- **只读审计 Skill + Python 库 + CLI**：检测 Claude Code / Codex 等 Agent 宿主的本地隐私与代理一致性，不动任何配置
- **本地面板**（`serve`）：零依赖、仅 127.0.0.1、自动审计 + 渐变进度条分数区 + 出口概览卡片 + DNS/WebRTC/TLS 独立小卡 + pill 式摘要
- **代码仓库安全扫描**（`repo`）：栈检测 + Semgrep/gitleaks/依赖审计 + 过期检测 + 0-100 评分 + SARIF 导出
- **动态徽章**（`badge`）：shield-badge.json + shields.io

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
- 版本号重置为 0.7
- CHANGELOG 历史已清除