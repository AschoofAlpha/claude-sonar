import unittest
import tempfile
import os
import subprocess
import json
import shutil
from pathlib import Path

class TestPrivacy(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.old_cwd = os.getcwd()
        os.chdir(self.temp_dir)
        
        self.fake_home = tempfile.mkdtemp()
        os.environ['USERPROFILE'] = self.fake_home
        os.environ['HOME'] = self.fake_home
        
        self.sensitive_values = [
            "192.0.2.10",
            "2001:db8::1",
            "C:\\Users\\SecretUser\\Documents",
            "/home/secretuser/docs",
            "secret-host-99",
            "SecretUser",
            "ghp_1234567890abcdef1234567890abcdef12345678",
            "session_id=1234567890abcdef",
            "proxypass",
            "secret_bearer_token_1234567890",
            "9876543210fedcba"
        ]

    def tearDown(self):
        os.chdir(self.old_cwd)
        def remove_readonly(func, path, _):
            import stat
            os.chmod(path, stat.S_IWRITE)
            try:
                func(path)
            except:
                pass
        shutil.rmtree(self.temp_dir, onerror=remove_readonly)
        shutil.rmtree(self.fake_home, onerror=remove_readonly)

    def test_privacy_leak_scan(self):
        from claude_sonar.redaction import Redactor
        redactor = Redactor()
        
        raw_data = {
            "System": {
                "Hostname": "secret-host-99",
                "Username": "SecretUser"
            },
            "Paths": [
                "C:\\Users\\SecretUser\\Documents",
                "/home/secretuser/docs",
                "C:\\Users\\SecretUser\\AppData\\Local\\Google\\Chrome\\User Data"
            ],
            "Token": "ghp_1234567890abcdef1234567890abcdef12345678",
            "Cookie": "session_id=1234567890abcdef",
            "IPs": ["192.0.2.10", "2001:db8::1"],
            "Network": "http://proxyuser:proxypass@192.0.2.20:8080",
            "Auth": "Bearer secret_bearer_token_1234567890",
            "Git": "SECRET_KEY=9876543210fedcba"
        }
        
        redacted = redactor.scan_and_redact(raw_data)
        out_str = json.dumps(redacted)
        
        for val in self.sensitive_values:
            self.assertNotIn(val, out_str, f"Found sensitive value {val} in output!")

if __name__ == '__main__':
    unittest.main()
