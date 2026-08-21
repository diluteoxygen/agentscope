"""
Unit and integration tests for the benchmark comparison suite.
"""

import unittest
import tempfile
import sys
import json
from pathlib import Path
from agentscope.benchmark import (
    run_benchmark_suite,
    AgentBenchmarkResult,
    BenchmarkSuiteResult,
)


class TestBenchmark(unittest.TestCase):
    def test_benchmark_suite_execution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            # Create two test tasks
            task_a = tmp_path / "agent_a.py"
            task_a.write_text("print('Agent A running')\n")

            task_b = tmp_path / "agent_b.py"
            task_b.write_text("with open('b_out.txt', 'w') as f: f.write('data')\n")

            tasks = [
                {"name": "agent-a", "command": [sys.executable, str(task_a)]},
                {"name": "agent-b", "command": [sys.executable, str(task_b)]}
            ]

            suite = run_benchmark_suite(tasks, cwd=str(tmp_path))
            self.assertEqual(len(suite.results), 2)
            self.assertEqual(suite.results[0].agent, "agent-a")
            self.assertEqual(suite.results[1].agent, "agent-b")
            self.assertGreaterEqual(suite.results[1].files_written_count, 1)

            # Test markdown table generation
            md_table = suite.to_markdown_table()
            self.assertIn("# Agent Authority Comparison Benchmark", md_table)
            self.assertIn("| `agent-a` |", md_table)
            self.assertIn("| `agent-b` |", md_table)

            # Test JSON export
            suite_dict = suite.to_dict()
            self.assertIn("timestamp", suite_dict)
            self.assertEqual(len(suite_dict["results"]), 2)


if __name__ == "__main__":
    unittest.main()
