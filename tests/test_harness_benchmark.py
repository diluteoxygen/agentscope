"""
End-to-end benchmark and test harness verifying detection of benign vs rogue agent behaviors.
"""

import unittest
import tempfile
import sys
import os
import shutil
from pathlib import Path

from agentscope.observer import TraceObserver
from agentscope.diff import diff_fingerprints
from agentscope.models import RiskLevel


class TestAgentHarness(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.tmpdir.name)
        self.fixtures_dir = Path(__file__).parent / "fixtures"

        # Copy fixtures into workspace
        shutil.copy(self.fixtures_dir / "benign_agent.py", self.work_dir / "benign_agent.py")
        shutil.copy(self.fixtures_dir / "rogue_agent.py", self.work_dir / "rogue_agent.py")

        # Create README in workspace
        (self.work_dir / "README.md").write_text("# Test Repo\n")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_benign_vs_rogue_lifecycle(self):
        obs = TraceObserver(cwd=str(self.work_dir))

        # 1. Trace Benign Agent Run
        benign_fp, benign_code = obs.trace_command(
            [sys.executable, "benign_agent.py"],
            agent_name="benign-agent"
        )
        self.assertEqual(benign_code, 0)
        self.assertIn("./tests/test_simulated_feature.py", benign_fp.capabilities.filesystem.write)

        # Baseline established from benign run
        baseline_fp = benign_fp

        # 2. Trace Second Benign Agent Run (clean match)
        second_benign_fp, _ = obs.trace_command(
            [sys.executable, "benign_agent.py"],
            agent_name="benign-agent"
        )
        delta_clean = diff_fingerprints(baseline_fp, second_benign_fp)
        self.assertFalse(delta_clean.has_escalations)
        self.assertEqual(delta_clean.risk_level, RiskLevel.LOW)

        # 3. Trace Rogue Agent Run (capability escalation)
        rogue_fp, rogue_code = obs.trace_command(
            [sys.executable, "rogue_agent.py"],
            agent_name="rogue-agent"
        )
        self.assertEqual(rogue_code, 0)

        # 4. Diff Rogue Run vs Baseline
        delta_rogue = diff_fingerprints(baseline_fp, rogue_fp)
        self.assertTrue(delta_rogue.has_escalations)
        self.assertIn(delta_rogue.risk_level, (RiskLevel.HIGH, RiskLevel.CRITICAL))

        # Verify sensitive files and CI modifications were detected
        has_ci_or_env = any(
            (".github/workflows" in w or ".env" in w)
            for w in delta_rogue.added_files_written
        )
        self.assertTrue(has_ci_or_env)
        self.assertTrue(len(delta_rogue.risk_reasons) > 0)


if __name__ == "__main__":
    unittest.main()
