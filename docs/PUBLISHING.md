# Publishing notes

## Version sources of truth

These three must match before tagging:

1. `pyproject.toml` → `[project].version`
2. `claude_sonar/__init__.py` → `__version__`
3. Git tag `vX.Y.Z` (no `dev` suffix on a stable release)

The publish workflow also requires `[project].name == claude-sonar`.

## PyPI package name

- **Current:** `claude-sonar` → https://pypi.org/project/claude-sonar/
- **Legacy:** `anti-claude-check` (older uploads; do not publish new versions there)

Agent Skill folder name matches the product: `claude-sonar` (invoke `$claude-sonar` / `/claude-sonar`).

## PyPI Trusted Publisher (OIDC)

Publish uses GitHub Actions OIDC against environment `pypi`.

Configure on the **claude-sonar** project (or as a pending publisher before first upload):

| Field | Value |
|---|---|
| Owner | `AschoofAlpha` |
| Repository | `claude-sonar` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

If the publisher was only added under the legacy `anti-claude-check` project, add the same publisher for `claude-sonar` (or pending) before tagging.

## Release / retag

```bash
git push origin main
gh release delete v1.2.0 -y || true
git push origin :refs/tags/v1.2.0 || true
git tag -d v1.2.0 2>/dev/null || true
git tag -a v1.2.0 -m "v1.2.0"
git push origin v1.2.0
gh release create v1.2.0 --title "v1.2.0 — Claude Sonar on PyPI" --generate-notes
```
