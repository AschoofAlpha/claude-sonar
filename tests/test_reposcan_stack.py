"""栈检测测试：lockfile/manifest 识别、pyproject 细化、源码兜底、目录跳过。"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_shield.reposcan.stack import scan_stack


class TestStackDetection(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="reposcan-stack-")
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _touch(self, rel: str, content: str = "") -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def _langs(self):
        return {s.language: s for s in scan_stack(self.root)}

    def test_empty_dir(self):
        self.assertEqual(scan_stack(self.root), [])

    def test_python_requirements(self):
        self._touch("requirements.txt")
        self._touch("app/main.py", "print('hi')\n")
        langs = self._langs()
        self.assertIn("Python", langs)
        self.assertIn("pip", langs["Python"].package_manager)
        files = langs["Python"].files
        self.assertIn("requirements.txt", files)

    def test_poetry_detected_from_pyproject(self):
        self._touch("pyproject.toml", "[tool.poetry]\nname = 'demo'\nversion = '1.0.0'\n")
        langs = self._langs()
        self.assertIn("Python", langs)
        self.assertEqual(langs["Python"].package_manager, "Poetry")

    def test_uv_detected_from_pyproject(self):
        self._touch("pyproject.toml", "[project]\nname = 'demo'\ndependencies = []\n\n[tool.uv]\npackage = true\n")
        langs = self._langs()
        self.assertIn("Python", langs)
        self.assertEqual(langs["Python"].package_manager, "uv")

    def test_python_managers_merged(self):
        self._touch("requirements.txt")
        self._touch("poetry.lock")
        langs = self._langs()
        self.assertIn("Python", langs)
        pm = langs["Python"].package_manager
        self.assertIn("pip", pm)
        self.assertIn("Poetry", pm)

    def test_js_go_and_rust(self):
        self._touch("package.json", '{"name": "x"}')
        self._touch("pnpm-lock.yaml")
        self._touch("go.mod", "module example.com/x\n\ngo 1.21\n")
        self._touch("Cargo.toml", "[package]\nname = 'x'\n")
        langs = self._langs()
        self.assertIn("JavaScript/TypeScript", langs)
        self.assertIn("Go", langs)
        self.assertIn("Rust", langs)
        js_pm = langs["JavaScript/TypeScript"].package_manager
        self.assertIn("npm", js_pm)
        self.assertIn("pnpm", js_pm)

    def test_java_php_ruby_csharp(self):
        self._touch("pom.xml", "<project/>")
        self._touch("composer.json", "{}")
        self._touch("Gemfile.lock")
        self._touch("App.csproj", "<Project/>")
        langs = self._langs()
        self.assertIn("Java", langs)
        self.assertIn("PHP", langs)
        self.assertIn("Ruby", langs)
        self.assertIn("C#", langs)

    def test_source_fallback_without_manifests(self):
        self._touch("src/app.py")
        self._touch("src/util.go")
        langs = self._langs()
        self.assertIn("Python", langs)
        self.assertIn("Go", langs)
        self.assertIn("(源码检测)", langs["Python"].package_manager)

    def test_skips_vendored_dirs(self):
        self._touch("package.json", "{}")
        self._touch("node_modules/dep/package.json", '{"name":"dep"}')
        self._touch("venv/lib/requirements.txt")
        self._touch("venv/lib/site-packages/x.py")
        self._touch("__pycache__/c.py")
        langs = self._langs()
        self.assertNotIn("requirements.txt", " ".join(langs["JavaScript/TypeScript"].files))
        # node_modules 里的 package.json 不得出现
        for f in langs["JavaScript/TypeScript"].files:
            self.assertNotIn("node_modules", f)

    def test_files_use_forward_slashes(self):
        self._touch("sub/dir/requirements.txt")
        langs = self._langs()
        self.assertTrue(any("sub/dir/requirements.txt" in f for f in langs["Python"].files))


if __name__ == "__main__":
    unittest.main()
