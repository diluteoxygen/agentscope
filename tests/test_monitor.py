"""
Unit tests for the live Terminal UI (TUI) monitor.
"""

import unittest
from agentscope.monitor import TerminalMonitor
from agentscope.models import RiskLevel


class TestMonitor(unittest.TestCase):
    def test_monitor_state_updates(self):
        monitor = TerminalMonitor(agent_name="antigravity")
        
        # 1. Normal file read
        monitor.update_with_line('[pid 100] openat(AT_FDCWD, "src/main.py", O_RDONLY) = 3')
        self.assertEqual(len(monitor.reads), 1)
        self.assertEqual(monitor.current_risk, RiskLevel.LOW)
        self.assertIn(100, monitor.active_pids)

        # 2. Command execution
        monitor.update_with_line('[pid 101] execve("/usr/bin/git", ["git", "status"], 0x0) = 0')
        self.assertIn("git", monitor.commands)
        self.assertIn(101, monitor.active_pids)

        # 3. Secret path access triggers CRITICAL risk
        monitor.update_with_line('[pid 102] openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY) = 4')
        self.assertEqual(len(monitor.secrets), 1)
        self.assertEqual(monitor.current_risk, RiskLevel.CRITICAL)

        # 4. Render multi-pane frame
        frame = monitor.render_frame(elapsed_sec=1.5, root_pid=100)
        self.assertIn("AGENTSCOPE REAL-TIME FORENSIC MONITOR", frame)
        self.assertIn("antigravity", frame)
        self.assertIn("CRITICAL", frame)
        self.assertIn("FILESYSTEM & EXECUTION", frame)
        self.assertIn("PERIMETER & SECRETS", frame)
        self.assertIn("LIVE FORENSIC EVENT STREAM", frame)


if __name__ == "__main__":
    unittest.main()
