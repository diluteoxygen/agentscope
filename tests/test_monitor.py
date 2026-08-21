"""
Unit tests for the live Terminal UI (TUI) monitor.
"""

import unittest
from agentscope.monitor import TerminalMonitor
from agentscope.models import RiskLevel


class TestMonitor(unittest.TestCase):
    def test_monitor_state_updates(self):
        monitor = TerminalMonitor(agent_name="test-agent")
        
        # 1. Normal file read
        monitor.update_with_line('[pid 100] openat(AT_FDCWD, "src/main.py", O_RDONLY) = 3')
        self.assertEqual(len(monitor.reads), 1)
        self.assertEqual(monitor.current_risk, RiskLevel.LOW)

        # 2. Command execution
        monitor.update_with_line('[pid 101] execve("/usr/bin/git", ["git", "status"], 0x0) = 0')
        self.assertIn("git", monitor.commands)

        # 3. Secret path access triggers CRITICAL risk
        monitor.update_with_line('[pid 102] openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY) = 4')
        self.assertEqual(len(monitor.secrets), 1)
        self.assertEqual(monitor.current_risk, RiskLevel.CRITICAL)

        # 4. Render ASCII frame
        frame = monitor.render_frame(elapsed_sec=1.5)
        self.assertIn("AGENTSCOPE REAL-TIME AUTHORITY MONITOR", frame)
        self.assertIn("test-agent", frame)
        self.assertIn("CRITICAL", frame)
        self.assertIn("READ: ./src/main.py", frame)


if __name__ == "__main__":
    unittest.main()
