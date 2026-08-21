"""
Unit tests for the Normalizer and sensitive resource classifier.
"""

import unittest
import tempfile
from pathlib import Path
from agentscope.normalizer import Normalizer, coalesce_paths


class TestNormalizer(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.cwd = Path(self.tmpdir.name)
        self.normalizer = Normalizer(cwd=str(self.cwd))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_path_normalization_workspace(self):
        file_path = self.cwd / "src" / "index.py"
        norm = self.normalizer.normalize_path(str(file_path))
        self.assertEqual(norm, "./src/index.py")

        root_norm = self.normalizer.normalize_path(str(self.cwd))
        self.assertEqual(root_norm, ".")

    def test_path_normalization_home(self):
        home_path = Path.home() / ".config" / "git" / "config"
        norm = self.normalizer.normalize_path(str(home_path))
        self.assertEqual(norm, "~/.config/git/config")

    def test_system_noise_filtering(self):
        self.assertTrue(self.normalizer.is_system_noise("/lib/x86_64-linux-gnu/libc.so.6"))
        self.assertTrue(self.normalizer.is_system_noise("/lib64/ld-linux-x86-64.so.2"))
        self.assertTrue(self.normalizer.is_system_noise("/usr/lib/locale/locale-archive"))
        self.assertTrue(self.normalizer.is_system_noise("/etc/ld.so.cache"))
        self.assertTrue(self.normalizer.is_system_noise("/dev/null"))
        self.assertTrue(self.normalizer.is_system_noise("/proc/self/cmdline"))
        self.assertTrue(self.normalizer.is_system_noise("/sys/devices/system/cpu"))

        self.assertFalse(self.normalizer.is_system_noise("/home/user/project/src/main.py"))
        self.assertFalse(self.normalizer.is_system_noise("/etc/hosts"))

    def test_sensitive_path_detection(self):
        ssh_sec = self.normalizer.detect_secrets("/home/user/.ssh/id_rsa")
        self.assertTrue(any("SSH Keys" in s for s in ssh_sec))

        aws_sec = self.normalizer.detect_secrets("/home/user/.aws/credentials")
        self.assertTrue(any("AWS Credentials" in s for s in aws_sec))

        env_sec = self.normalizer.detect_secrets(str(self.cwd / ".env"))
        self.assertTrue(any("Environment Secrets" in s for s in env_sec))

        ci_sec = self.normalizer.detect_secrets(str(self.cwd / ".github" / "workflows" / "ci.yml"))
        self.assertTrue(any("CI/CD" in s for s in ci_sec))

        pem_sec = self.normalizer.detect_secrets(str(self.cwd / "server.pem"))
        self.assertTrue(any("Cryptographic Key" in s for s in pem_sec))

    def test_sensitive_env_detection(self):
        env_sec = self.normalizer.detect_secrets("dummy_path", env_vars=["GITHUB_TOKEN", "USER", "PATH"])
        self.assertIn("env:GITHUB_TOKEN", env_sec)
        self.assertNotIn("env:USER", env_sec)
        self.assertNotIn("env:PATH", env_sec)

    def test_build_capabilities_complete(self):
        caps = self.normalizer.build_capabilities(
            raw_reads={str(self.cwd / "src" / "a.py"), "/etc/ld.so.cache", str(Path.home() / ".ssh" / "known_hosts")},
            raw_writes={str(self.cwd / ".github" / "workflows" / "deploy.yml")},
            raw_commands={"/usr/bin/curl", "git"},
            raw_network={" api.github.com:443 "},
            raw_env_accessed={"AWS_SECRET_ACCESS_KEY", "HOME"}
        )

        self.assertEqual(caps.filesystem.read, ["./src/a.py", "~/.ssh/known_hosts"])
        self.assertEqual(caps.filesystem.write, ["./.github/workflows/deploy.yml"])
        self.assertEqual(caps.commands, ["curl", "git"])
        self.assertEqual(caps.network, ["api.github.com:443"])
        self.assertTrue(any("CI/CD" in s for s in caps.secrets))
        self.assertIn("env:AWS_SECRET_ACCESS_KEY", caps.secrets)

    def test_coalesce_paths(self):
        paths = [
            "./src/utils/a.py",
            "./src/utils/b.py",
            "./src/utils/c.py",
            "./src/utils/d.py",
            "./src/utils/e.py",
            "./src/main.py",
            "./package.json",
        ]
        coalesced = coalesce_paths(paths, threshold=5)
        self.assertIn("./src/utils/**", coalesced)
        self.assertIn("./src/main.py", coalesced)
        self.assertIn("./package.json", coalesced)
        self.assertNotIn("./src/utils/a.py", coalesced)


if __name__ == "__main__":
    unittest.main()
