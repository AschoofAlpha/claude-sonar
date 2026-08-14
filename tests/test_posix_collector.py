import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_sonar.collectors.posix import (
    _active_content,
    _active_one,
    _present,
    _privacy_rows,
    collect_posix_snapshot,
    main as posix_main,
)


class TestPosixCollector(unittest.TestCase):
    def test_snapshot_shape(self):
        snap = collect_posix_snapshot()
        self.assertEqual(snap["SchemaVersion"], 7)
        self.assertEqual(snap["System"]["Platform"], "POSIX")
        self.assertIn("ProxyEnvironmentVariables", snap["System"])
        self.assertIn("ClaudeCode", snap)
        self.assertIn("DisableTelemetryActive", snap["ClaudeCode"])
        # Must not embed env values
        blob = str(snap)
        self.assertNotIn("Value", blob)

    def test_privacy_rows_no_value_leak(self):
        os.environ["CLAUDE_SHIELD_TEST_SECRET"] = "file:/private/trace"
        try:
            rows = _privacy_rows("CLAUDE_SHIELD_TEST_SECRET", mode="content")
            self.assertTrue(rows[0]["Present"])
            self.assertTrue(rows[0]["Active"])
            self.assertNotIn("Value", rows[0])
            self.assertNotIn("private", str(rows))
        finally:
            os.environ.pop("CLAUDE_SHIELD_TEST_SECRET", None)

    def test_self_test_main(self):
        rc = posix_main(["--self-test"])
        self.assertEqual(rc, 0)

    def test_active_helpers(self):
        os.environ.pop("CLAUDE_SHIELD_FLAG", None)
        self.assertFalse(_present("CLAUDE_SHIELD_FLAG"))
        os.environ["CLAUDE_SHIELD_FLAG"] = "0"
        self.assertTrue(_present("CLAUDE_SHIELD_FLAG"))
        self.assertFalse(_active_one("CLAUDE_SHIELD_FLAG"))
        os.environ["CLAUDE_SHIELD_FLAG"] = "1"
        self.assertTrue(_active_one("CLAUDE_SHIELD_FLAG"))
        os.environ["CLAUDE_SHIELD_FLAG"] = "file:x"
        self.assertTrue(_active_content("CLAUDE_SHIELD_FLAG"))
        os.environ.pop("CLAUDE_SHIELD_FLAG", None)


if __name__ == "__main__":
    unittest.main()
