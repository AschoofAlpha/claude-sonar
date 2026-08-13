"""修复建议生成：对高严重度 finding 输出人类可读建议（只建议、不自动改文件）。"""

from __future__ import annotations

from typing import Any, Dict

# (匹配关键字, 建议) — 按顺序匹配 finding 的 tool+rule_id 小写串
_RULES = [
    (("sql-injection", "nosql"), 
     "注入风险：使用参数化查询（预编译语句 / ORM 绑定参数），禁止把用户输入直接拼接进 SQL 或 NoSQL 查询字符串。"),
    (("command-injection", "os-system", "subprocess-shell"),
     "命令注入：改用参数数组调用进程（如 subprocess.run([...], shell=False) / execFile），不要拼接 shell 字符串、不要对动态输入使用 shell=True。"),
    (("xss",),
     "XSS：对输出做上下文相关的转义（HTML 转义 / 使用框架的自动转义机制），避免把用户输入直接写入 innerHTML、document.write 或模板。"),
    (("hardcoded", "secret", "password", "credential", "gitleaks"),
     "硬编码密钥：把密钥移入环境变量或密钥管理服务（.env + 密钥库），并尽快轮换已泄露的密钥；若已提交进 git 历史，需要清理历史（git filter-repo 等）并轮换。"),
    (("deserialization", "pickle", "unserialize", "yaml"),
     "不安全反序列化：不要反序列化不可信数据；改用 JSON 等安全格式，或对数据做签名/白名单校验后再处理。"),
    (("path-traversal",),
     "路径穿越：对文件路径做规范化与白名单校验（resolve 后必须落在允许目录内），拒绝 .. 与绝对路径。"),
    (("ssrf",),
     "SSRF：校验目标 URL 的协议与域名白名单，禁止直连内网地址，必要时加 DNS 重绑定防护。"),
    (("weak-crypto", "md5", "sha1", "insecure-random", "weak-random"),
     "弱加密/弱随机：改用 SHA-256+、AES-GCM 等现代算法；口令哈希用 bcrypt/argon2；随机数使用密码学安全源（secrets / crypto）。"),
    (("insecure-tls",),
     "TLS 配置不安全：启用证书校验（不要跳过验证），最低使用 TLS 1.2，避免弱密码套件。"),
    (("xxe",),
     "XXE：禁用 DTD 与外部实体（如 XMLConstants.FEATURE_SECURE_PROCESSING），避免解析不可信 XML。"),
    (("eval",),
     "动态代码执行：避免 eval / new Function / exec 执行动态代码；改用白名单解析或纯函数方案。"),
    (("prototype-pollution",),
     "原型链污染：合并对象时过滤 __proto__ / constructor / prototype 等危险键。"),
    (("unsafe-block",),
     "Rust unsafe：审查 unsafe 块的边界，确保裸指针/FFI 调用有明确的安全不变量，并尽量缩小 unsafe 范围。"),
    (("insecure-deserialization",),
     "不安全反序列化：不要反序列化不可信数据；改用 JSON 等安全格式，或对数据做签名/白名单校验后再处理。"),
    (("file-inclusion",),
     "文件包含：避免用用户输入拼接 include/require 路径；改用白名单映射，禁止远程包含。"),
    (("csrf",),
     "CSRF 防护缺失：启用框架的 CSRF 令牌机制，并为状态变更请求强制校验。"),
]


def suggestion_for(finding: Dict[str, Any]) -> str:
    """按 tool+rule_id 关键词匹配生成建议；无匹配时给通用建议。"""
    key = f"{finding.get('tool', '')} {finding.get('rule_id', '')}".lower()
    for needles, advice in _RULES:
        if any(n in key for n in needles):
            return advice
    return ("请结合代码上下文人工确认该处输入来源是否可信，"
            "并按对应漏洞类别加固（详见规则说明）。")
