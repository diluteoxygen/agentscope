"""
Unit tests for the sandbox policy exporter.
"""

import unittest
import tempfile
import json
from pathlib import Path
from agentscope.models import CapabilityFingerprint, Capabilities, FilesystemCapabilities
from agentscope.policy import export_docker_flags, export_seccomp_profile, export_bwrap_command
from agentscope.cli import build_parser, cmd_export_policy


class TestPolicyExporter(unittest.TestCase):
    def setUp(self):
        self.fp = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/app.py"], write=["./build/bundle.js"]),
                commands=["npm"],
                network=["registry.npmjs.org:443"],
                secrets=[]
            )
        )
        self.fp_isolated = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/app.py"]),
                commands=[],
                network=[],
                secrets=[]
            )
        )

    def test_docker_flags_network_and_isolation(self):
        flags = export_docker_flags(self.fp)
        self.assertIn("--network=bridge", flags)
        self.assertIn("--cap-drop=ALL", flags)
        self.assertIn("--read-only", flags)

        isolated_flags = export_docker_flags(self.fp_isolated)
        self.assertIn("--network=none", flags := isolated_flags)

    def test_seccomp_profile_generation(self):
        profile = export_seccomp_profile(self.fp)
        self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")
        self.assertIn("SCMP_ARCH_X86_64", profile["architectures"])
        
        allowed = profile["syscalls"][0]["names"]
        self.assertIn("openat", allowed)
        self.assertIn("execve", allowed)
        self.assertIn("connect", allowed)

    def test_bwrap_command_generation(self):
        bwrap_args = export_bwrap_command(self.fp, base_command=["npm", "start"])
        self.assertIn("bwrap", bwrap_args)
        self.assertIn("--ro-bind", bwrap_args)
        self.assertIn("./build/bundle.js", bwrap_args)
        self.assertIn("npm", bwrap_args)

    def test_cli_export_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            in_fp = tmp_path / "base.json"
            out_seccomp = tmp_path / "seccomp.json"

            in_fp.write_text(self.fp.to_json())

            parser = build_parser()
            args = parser.parse_args(["export-policy", "--format", "seccomp", "--input", str(in_fp), "--output", str(out_seccomp)])
            rc = cmd_export_policy(args)
            self.assertEqual(rc, 0)
            self.assertTrue(out_seccomp.exists())
            
            data = json.loads(out_seccomp.read_text())
            self.assertEqual(data["defaultAction"], "SCMP_ACT_ERRNO")


if __name__ == "__main__":
    unittest.main()
