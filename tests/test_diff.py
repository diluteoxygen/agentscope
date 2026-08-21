"""
Unit tests for the diff engine, delta calculations, and risk severity ratings.
"""

import unittest
import json
from agentscope.models import (
    CapabilityFingerprint,
    Capabilities,
    FilesystemCapabilities,
    RiskLevel,
)
from agentscope.diff import diff_fingerprints, format_terminal_diff


class TestDiffEngine(unittest.TestCase):
    def test_clean_match(self):
        fp1 = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/app.py"], write=["./src/out.txt"]),
                commands=["pytest"],
                network=["api.github.com:443"],
                secrets=[]
            )
        )
        fp2 = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/app.py"], write=["./src/out.txt"]),
                commands=["pytest"],
                network=["api.github.com:443"],
                secrets=[]
            )
        )
        delta = diff_fingerprints(fp1, fp2)
        self.assertFalse(delta.has_escalations)
        self.assertEqual(delta.risk_level, RiskLevel.LOW)
        self.assertEqual(delta.risk_reasons, [])

    def test_critical_risk_secret_escalation(self):
        base = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/app.py"]),
                commands=["git"],
                network=[],
                secrets=[]
            )
        )
        cand = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/app.py"]),
                commands=["git"],
                network=[],
                secrets=["env:GITHUB_TOKEN", "~/.ssh/id_rsa (SSH Keys & Configuration)"]
            )
        )
        delta = diff_fingerprints(base, cand)
        self.assertTrue(delta.has_escalations)
        self.assertEqual(delta.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(len(delta.added_secrets), 2)
        self.assertTrue(any("secret" in r.lower() for r in delta.risk_reasons))

    def test_high_risk_workflow_modification(self):
        base = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/app.py"], write=["./src/app.py"]),
                commands=["git"]
            )
        )
        cand = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(
                    read=["./src/app.py"],
                    write=["./src/app.py", "./.github/workflows/ci.yml"]
                ),
                commands=["git"]
            )
        )
        delta = diff_fingerprints(base, cand)
        self.assertTrue(delta.has_escalations)
        self.assertEqual(delta.risk_level, RiskLevel.HIGH)
        self.assertIn("./.github/workflows/ci.yml", delta.added_files_written)
        self.assertTrue(any("CI/CD" in r for r in delta.risk_reasons))

    def test_medium_risk_binary_execution(self):
        base = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/app.py"]),
                commands=["git", "pytest"]
            )
        )
        cand = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/app.py"]),
                commands=["git", "pytest", "curl", "docker"]
            )
        )
        delta = diff_fingerprints(base, cand)
        self.assertTrue(delta.has_escalations)
        self.assertEqual(delta.risk_level, RiskLevel.MEDIUM)
        self.assertEqual(delta.added_commands, ["curl", "docker"])

    def test_terminal_and_json_formatting(self):
        base = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/a.py"])
            )
        )
        cand = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(
                    read=["./src/a.py", "~/.config/gh/hosts.yml"],
                    write=["./src/b.py"]
                ),
                commands=["curl"],
                network=["api.stripe.com:443"],
                secrets=["env:STRIPE_API_KEY"]
            )
        )
        delta = diff_fingerprints(base, cand)
        
        # Test terminal formatting
        term_diff = format_terminal_diff(delta)
        self.assertIn("SECRETS", term_diff)
        self.assertIn("env:STRIPE_API_KEY", term_diff)
        self.assertIn("FILES WRITTEN", term_diff)
        self.assertIn("COMMANDS", term_diff)
        self.assertIn("curl", term_diff)
        self.assertIn("NETWORK", term_diff)
        self.assertIn("api.stripe.com:443", term_diff)
        self.assertIn("RISK DELTA: CRITICAL", term_diff)

        # Test JSON serialization
        d_dict = delta.to_dict()
        self.assertTrue(d_dict["has_escalations"])
        self.assertEqual(d_dict["risk_level"], "CRITICAL")
        self.assertIn("env:STRIPE_API_KEY", d_dict["added"]["secrets"])
        self.assertIn("curl", d_dict["added"]["commands"])
        self.assertIn("api.stripe.com:443", d_dict["added"]["network"])
        self.assertIn("./src/b.py", d_dict["added"]["files_written"])


if __name__ == "__main__":
    unittest.main()
