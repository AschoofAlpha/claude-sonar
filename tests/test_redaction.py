import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from claude_shield.redaction import Redactor

class TestRedactor(unittest.TestCase):
    def setUp(self):
        self.redactor = Redactor()

    def test_ipv4_variations(self):
        res = self.redactor.scan_and_redact("192.0.2.10")
        self.assertTrue(res.startswith("<IPV4:"))
        
        res = self.redactor.scan_and_redact("192.0.2.10:7890")
        self.assertTrue(res.startswith("<IPV4:"))
        self.assertTrue(res.endswith(":7890"))
        
        res = self.redactor.scan_and_redact("198.51.100.0/24")
        self.assertTrue(res.startswith("<IPV4:"))
        self.assertTrue(res.endswith("/24"))

    def test_ipv6_variations(self):
        res = self.redactor.scan_and_redact("[2001:db8::10]:443")
        self.assertTrue("<IPV6:" in res)
        self.assertTrue(res.endswith("]:443"))

    def test_urls(self):
        res = self.redactor.scan_and_redact("http://192.0.2.10:9090/api")
        self.assertTrue("<IPV4:" in res)
        
        res = self.redactor.scan_and_redact("https://user:pass123@example.com/api")
        self.assertTrue("<USER:" in res)
        self.assertTrue("<CRED:" in res)
        self.assertTrue("example.com" in res)

    def test_paths(self):
        res = self.redactor.scan_and_redact("C:\\Users\\Bob\\project")
        self.assertTrue("<PATH:" in res)
        
        res = self.redactor.scan_and_redact("/home/alice/project")
        self.assertTrue("<PATH:" in res)
        
        res = self.redactor.scan_and_redact("\\\\SERVER\\Share\\path")
        self.assertTrue("<PATH:" in res)

    def test_credentials(self):
        res = self.redactor.scan_and_redact("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI...")
        self.assertTrue("<CRED:" in res)
        self.assertTrue("Bearer " in res)
        
        res = self.redactor.scan_and_redact("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
        self.assertTrue("<CRED:" in res)
        
        res = self.redactor.scan_and_redact("token=ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        self.assertTrue("<CRED:" in res)
        
        res = self.redactor.scan_and_redact("-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQC...")
        self.assertEqual(res, "<PRIVATE_KEY_REDACTED>")

    def test_recursive_data(self):
        data = {
            "token": "sk-ant-api03-invalid-test-token-123",
            "ssid": "MyHomeNetwork",
            "list": ["192.0.2.10", {"nested": "198.51.100.20"}],
            "num": 42,
            "bool": True,
            "none": None
        }
        res = self.redactor.scan_and_redact(data)
        self.assertTrue(res["token"].startswith("<CRED:"))
        self.assertTrue(res["ssid"].startswith("<CRED:"))
        self.assertTrue(res["list"][0].startswith("<IPV4:"))
        self.assertTrue(res["list"][1]["nested"].startswith("<IPV4:"))
        self.assertEqual(res["num"], 42)
        self.assertEqual(res["bool"], True)
        self.assertIsNone(res["none"])

    def test_circular_reference(self):
        a = []
        a.append(a)
        res = self.redactor.scan_and_redact(a)
        self.assertEqual(res, ["<CIRCULAR_REFERENCE>"])

    def test_long_string(self):
        s = "a" * 100001
        res = self.redactor.scan_and_redact(s)
        self.assertEqual(res, "<TRUNCATED_LONG_STRING>")

    def test_binary_data(self):
        res = self.redactor.scan_and_redact(b'\xff\xfe\x00\x01')
        self.assertEqual(res, "<BINARY_DATA>")

    def test_locale_slash_not_path(self):
        text = "Culture/UICulture/SystemLocale differ."
        res = self.redactor.scan_and_redact(text)
        self.assertEqual(res, text)
        self.assertNotIn("<PATH:", res)

    def test_real_posix_home_still_redacted(self):
        res = self.redactor.scan_and_redact("/home/alice/project")
        self.assertIn("<PATH:", res)

if __name__ == '__main__':
    unittest.main()
