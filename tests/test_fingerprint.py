"""
Unit tests for AgentScope models, normalizer, and diff engine.
Compatible with standard library unittest and pytest.
"""

import unittest
import tempfile
from pathlib import Path
from agentscope.models import (
    CapabilityFingerprint,
    Capabilities,
    FilesystemCapabilities,
    RiskLevel,
)
from agentscope.normalizer import Normalizer
from agentscope.diff import diff_fingerprints, format_terminal_diff


class TestAgentScope(unittest.TestCase):
    def test_fingerprint_serialization(self):
        fp = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(
                    read=["src/a.py", "src/b.py"],
                    write=["src/out.txt"]
                ),
                commands=["git", "pytest"],
                network=["api.github.com"],
                secrets=["GITHUB_TOKEN"]
            )
        )
        json_data = fp.to_json()
        reloaded = CapabilityFingerprint.from_json(json_data)
        self.assertEqual(reloaded.capabilities.filesystem.read, ["src/a.py", "src/b.py"])
        self.assertEqual(reloaded.capabilities.commands, ["git", "pytest"])
        self.assertEqual(reloaded.capabilities.network, ["api.github.com"])
        self.assertEqual(reloaded.capabilities.secrets, ["GITHUB_TOKEN"])

    def test_normalizer_path_normalization(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            norm = Normalizer(cwd=str(tmp_path))
            file_in_cwd = tmp_path / "src" / "main.py"
            self.assertEqual(norm.normalize_path(str(file_in_cwd)), "./src/main.py")

            self.assertTrue(norm.is_system_noise("/lib/x86_64-linux-gnu/libc.so.6"))
            self.assertTrue(norm.is_system_noise("/etc/ld.so.cache"))
            self.assertFalse(norm.is_system_noise("/home/user/project/src/main.py"))

    def test_diff_clean_match(self):
        fp1 = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/a.py"], write=["./src/b.py"]),
                commands=["git"],
                network=["api.github.com"]
            )
        )
        fp2 = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/a.py"], write=["./src/b.py"]),
                commands=["git"],
                network=["api.github.com"]
            )
        )
        delta = diff_fingerprints(fp1, fp2)
        self.assertFalse(delta.has_escalations)
        self.assertEqual(delta.risk_level, RiskLevel.LOW)

    def test_diff_risk_escalation(self):
        base = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/a.py"]),
                commands=["npm"],
                network=["registry.npmjs.org"]
            )
        )
        candidate = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(
                    read=["./src/a.py", "~/.ssh/id_rsa"],
                    write=[".github/workflows/ci.yml"]
                ),
                commands=["npm", "curl"],
                network=["registry.npmjs.org", "192.168.1.100:443"],
                secrets=["GITHUB_TOKEN"]
            )
        )
        delta = diff_fingerprints(base, candidate)
        self.assertTrue(delta.has_escalations)
        self.assertEqual(delta.risk_level, RiskLevel.CRITICAL)
        self.assertIn("curl", delta.added_commands)
        self.assertIn("192.168.1.100:443", delta.added_network)
        self.assertIn("GITHUB_TOKEN", delta.added_secrets)

        formatted = format_terminal_diff(delta)
        self.assertIn("SECRETS", formatted)
        self.assertIn("GITHUB_TOKEN", formatted)
        self.assertIn("RISK DELTA: CRITICAL", formatted)


if __name__ == "__main__":
    unittest.main()
