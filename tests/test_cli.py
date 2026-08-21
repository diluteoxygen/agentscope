"""
Integration tests for AgentScope CLI workflows.
"""

import unittest
import tempfile
import sys
from pathlib import Path
from agentscope.cli import build_parser, cmd_run, cmd_baseline, cmd_diff, cmd_verify
from agentscope.models import CapabilityFingerprint, Capabilities, FilesystemCapabilities


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_cli_parser_commands(self):
        parser = build_parser()
        args = parser.parse_args(["run", "--agent", "claude", "--", "echo", "hello"])
        self.assertEqual(args.subcommand, "run")
        self.assertEqual(args.agent, "claude")
        self.assertEqual(args.command, ["--", "echo", "hello"])

    def test_cli_baseline_and_verify_clean(self):
        fp_path = self.work_dir / "run.json"
        baseline_path = self.work_dir / ".agent" / "authority-baseline.json"

        fp = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/main.py"], write=["./src/out.txt"]),
                commands=["pytest"],
                network=["api.github.com:443"]
            )
        )
        fp_path.write_text(fp.to_json())

        # Establish baseline
        parser = build_parser()
        args_base = parser.parse_args(["baseline", "--input", str(fp_path), "--output", str(baseline_path)])
        rc_base = cmd_baseline(args_base)
        self.assertEqual(rc_base, 0)
        self.assertTrue(baseline_path.exists())

        # Verify clean match
        args_ver = parser.parse_args(["verify", "--candidate", str(fp_path), "--baseline", str(baseline_path)])
        rc_ver = cmd_verify(args_ver)
        self.assertEqual(rc_ver, 0)

    def test_cli_verify_escalation_failure(self):
        baseline_path = self.work_dir / "base.json"
        candidate_path = self.work_dir / "cand.json"

        base_fp = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/main.py"]),
                commands=["git"]
            )
        )
        cand_fp = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/main.py"]),
                commands=["git", "curl"],
                secrets=["env:AWS_SECRET_ACCESS_KEY"]
            )
        )
        baseline_path.write_text(base_fp.to_json())
        candidate_path.write_text(cand_fp.to_json())

        parser = build_parser()
        args_ver = parser.parse_args(["verify", "--candidate", str(candidate_path), "--baseline", str(baseline_path)])
        rc_ver = cmd_verify(args_ver)
        self.assertEqual(rc_ver, 1)

    def test_cli_diff_command(self):
        path_a = self.work_dir / "a.json"
        path_b = self.work_dir / "b.json"

        fp_a = CapabilityFingerprint(capabilities=Capabilities(commands=["git"]))
        fp_b = CapabilityFingerprint(capabilities=Capabilities(commands=["git", "pytest"]))

        path_a.write_text(fp_a.to_json())
        path_b.write_text(fp_b.to_json())

        parser = build_parser()
        args_diff = parser.parse_args(["diff", str(path_a), str(path_b), "--json"])
        rc_diff = cmd_diff(args_diff)
        self.assertEqual(rc_diff, 0)


if __name__ == "__main__":
    unittest.main()
