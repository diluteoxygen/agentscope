"""
Unit and integration tests for active runtime enforcement.
"""

import unittest
import tempfile
import sys
from pathlib import Path
from agentscope.models import CapabilityFingerprint, Capabilities, FilesystemCapabilities
from agentscope.enforce import EnforcementEngine, EnforcementViolation
from agentscope.cli import build_parser, cmd_enforce


class TestEnforce(unittest.TestCase):
    def setUp(self):
        self.baseline = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/main.py"], write=["./build/bundle.js"]),
                commands=["git", "npm", "python3"],
                network=["api.github.com:443"],
                secrets=[]
            )
        )
        self.engine = EnforcementEngine(baseline=self.baseline, strict_mode=True)

    def test_check_violation_allowed_actions(self):
        # 1. Allowed file open
        v1 = self.engine.check_violation('[pid 100] openat(AT_FDCWD, "src/main.py", O_RDONLY) = 3')
        self.assertIsNone(v1)

        # 2. Allowed exec
        v2 = self.engine.check_violation('[pid 100] execve("/usr/bin/git", ["git", "status"], 0x0) = 0')
        self.assertIsNone(v2)

    def test_check_violation_unauthorized_secret(self):
        # Unauthorized access to ~/.ssh/id_rsa
        v = self.engine.check_violation('[pid 101] openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY) = 4')
        self.assertIsNotNone(v)
        self.assertEqual(v.violation_type, "SECRET_ACCESS")
        self.assertIn(".ssh/id_rsa", v.target)

    def test_check_violation_unauthorized_write(self):
        # Unauthorized write to .github/workflows/deploy.yml
        v = self.engine.check_violation('[pid 102] openat(AT_FDCWD, ".github/workflows/deploy.yml", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 5')
        self.assertIsNotNone(v)
        self.assertEqual(v.violation_type, "UNAUTHORIZED_WRITE")

    def test_check_violation_unauthorized_exec(self):
        # Unauthorized execution of curl in strict mode
        v = self.engine.check_violation('[pid 103] execve("/usr/bin/curl", ["curl", "https://evil.com"], 0x0) = 0')
        self.assertIsNotNone(v)
        self.assertEqual(v.violation_type, "UNAUTHORIZED_EXEC")
        self.assertEqual(v.target, "curl")

    def test_enforce_clean_execution(self):
        # Run a simple harmless python command allowed by baseline
        v, code = self.engine.enforce_command([sys.executable, "-c", "print('hello world')"])
        self.assertIsNone(v)
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
