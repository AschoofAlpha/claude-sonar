# Security Policy

## Reporting a Vulnerability

Claude Shield is a read-only local audit tool, but the collector and analysis
libraries still need to be trustworthy: if an attacker-controlled config file
or a malicious policy chain could trick the collector into acting outside its
read-only boundary, that is a security issue.

**Please do not open a public issue for security vulnerabilities.** Report
them privately instead:

- Email: `w1586956317@gmail.com` (the repository owner)
- Or open a [GitHub Security Advisory](https://github.com/AschoofAlpha/claude-shield/security/advisories/new)

You should receive a response within 48 hours. If you do not, follow up by
opening a private issue with the `security` label.

## What counts as a vulnerability

- Collector or analyzer executing commands beyond the documented read-only scope.
- Redaction failures that leak local identifiers (IPs, MAC addresses, usernames,
  paths) into shared output.
- Credential exposure in logs, reports, or error messages.
- Path traversal or config injection via `Mihomo`/`ClaudeCode` config parsing.

## What is not a vulnerability

- The tool not predicting or preventing account review/suspension. This is an
  explicit boundary: Claude Shield produces local evidence and never promises
  to bypass platform review.
- Third-party detector labels being opinions until corroborated by live routing
  evidence.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.3.x   | ✅ |
| 1.2.x   | ✅ |
| < 1.2.0 | ❌ |
