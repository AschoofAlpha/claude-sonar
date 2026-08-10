# Publishing notes

## Version sources of truth

These three must match before tagging:

1. `pyproject.toml` → `[project].version`
2. `claude_shield/__init__.py` → `__version__`
3. Git tag `vX.Y.Z` (no `dev` suffix on a stable release)

The publish workflow fails closed if the tag does not equal both package versions.

## PyPI Trusted Publisher (required)

Publish uses OIDC trusted publishing against GitHub Environment `pypi`.

Configure at:
https://pypi.org/manage/project/anti-claude-check/settings/publishing/

Exact claims the workflow presents:

| Claim | Value |
|---|---|
| Owner | `AschoofAlpha` |
| Repository | `claude-shield` |
| Workflow filename | `publish.yml` |
| Environment name | `pypi` |

If Environment is left blank on PyPI while the workflow sets `environment: pypi`, publish fails with:

`invalid-publisher: valid token, but no corresponding publisher`

GitHub Environment `pypi` already exists on the repo. After the PyPI side matches, push a tag:

```bash
git tag -a v1.2.0 -m "v1.2.0"
git push origin main
git push origin v1.2.0
```

If an earlier broken `v1.2.0` tag/release exists, delete it first, then recreate on the corrected commit:

```bash
gh release delete v1.2.0 -y
git push origin :refs/tags/v1.2.0
git tag -d v1.2.0 2>/dev/null || true
git tag -a v1.2.0 -m "v1.2.0"
git push origin v1.2.0
gh release create v1.2.0 --title "v1.2.0 — privacy fixes & offline-by-default" --notes-file CHANGELOG.md
```

Package name on PyPI remains **`anti-claude-check`**.
