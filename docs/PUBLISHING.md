# Publishing notes

## Version sources of truth

These three must match before tagging:

1. `pyproject.toml` → `[project].version`
2. `claude_shield/__init__.py` → `__version__`
3. Git tag `vX.Y.Z` (no `dev` suffix on a stable release)

The publish workflow fails closed if the tag does not equal both package versions.

## PyPI auth (API token)

Publish uses a **PyPI API token** stored as the repo secret `PYPI_API_TOKEN`.

1. Create a token at https://pypi.org/manage/account/token/  
   - Scope: project `anti-claude-check` (preferred) or entire account  
   - Copy the value once (`pypi-...`)
2. Store it on GitHub (do **not** paste into chat):

```bash
# from the repo directory; gh prompts for the secret value on stdin
gh secret set PYPI_API_TOKEN -R AschoofAlpha/claude-shield
```

Or: repo → Settings → Secrets and variables → Actions → New repository secret  
Name: `PYPI_API_TOKEN` · Value: the `pypi-...` token

Trusted Publisher / OIDC is optional and currently unused by the workflow.

After the secret exists, push a tag:

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
