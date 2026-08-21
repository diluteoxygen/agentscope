"""
Unit tests for the eBPF kernel driver interface.
"""

import unittest
from agentscope.ebpf.driver import EBPFDriver


class TestEBPFDriver(unittest.TestCase):
    def test_ebpf_event_parsing(self):
        driver = EBPFDriver()
        
        # Test open event
        r, w, c = driver.parse_event(event_type=1, comm="python3", path="/repo/src/app.py")
        self.assertIn("/repo/src/app.py", r)

        # Test exec event
        r2, w2, c2 = driver.parse_event(event_type=2, comm="bash", path="/usr/bin/git")
        self.assertIn("/usr/bin/git", c2)

    def test_support_detection(self):
        # Unprivileged user shouldn't crash
        supported = EBPFDriver.is_supported()
        self.assertIsInstance(supported, bool)


if __name__ == "__main__":
    unittest.main()
