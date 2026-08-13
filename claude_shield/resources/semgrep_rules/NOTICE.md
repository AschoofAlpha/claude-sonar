# NOTICE — 内置 Semgrep 规则来源说明

本目录（`claude_shield/resources/semgrep_rules/`）下的 YAML 规则文件：

- `python.yaml`（6 条）
- `javascript.yaml`（6 条）
- `java.yaml`（5 条）
- `go.yaml`（5 条）
- `php.yaml`（5 条）
- `ruby.yaml`（5 条）
- `rust.yaml`（5 条）
- `csharp.yaml`（5 条）

是以下开源项目规则集的**精简子集**（每语言保留 3-6 条核心规则，覆盖 SQL 注入、
命令注入、XSS、硬编码密钥、不安全反序列化等；规则文本未作语义修改，仅增补了
各文件头部的来源注释）：

- 项目：alissonlinneker/shield-claude-skill
- 上游路径：`configs/semgrep-rules/`
- 仓库地址：https://github.com/alissonlinneker/shield-claude-skill
- 许可证：MIT License，Copyright (c) 2026 ALASTecnology

MIT License 全文：https://github.com/alissonlinneker/shield-claude-skill/blob/main/LICENSE

MIT 许可要点（非法律文本，仅摘要）：
允许自由使用、复制、修改、分发本规则（含商用），但须保留上述版权与许可声明，
且按“原样”提供、不附带任何担保。

claude-shield 其余代码（reposcan 模块、评分、报告、编排逻辑等）为原创实现，
遵循项目根目录 `LICENSE`（MIT）。
