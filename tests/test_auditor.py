"""
Unit and integration tests for the in-process LD_PRELOAD environment variable auditor.
"""

import unittest
import tempfile
import sys
import os
import subprocess
import ctypes
from pathlib import Path
from agentscope.auditor import get_or_build_shim, EnvAuditor
from agentscope.observer import TraceObserver


class TestEnvAuditor(unittest.TestCase):
    def test_shim_build(self):
        shim_path = get_or_build_shim()
        self.assertIsNotNone(shim_path)
        self.assertTrue(shim_path.exists())

    def test_in_process_env_interception(self):
        auditor = EnvAuditor()
        self.assertTrue(auditor.enabled)

        # Run child process that calls libc getenv via ctypes
        script = (
            "import ctypes\n"
            "libc = ctypes.CDLL(None)\n"
            "libc.getenv.argtypes = [ctypes.c_char_p]\n"
            "libc.getenv.restype = ctypes.c_char_p\n"
            "_ = libc.getenv(b'OPENAI_API_KEY')\n"
            "_ = libc.getenv(b'GITHUB_TOKEN')\n"
            "_ = libc.getenv(b'CUSTOM_BENIGN_VAR')\n"
        )

        injected = auditor.get_injected_env()
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            env=injected
        )
        self.assertEqual(proc.returncode, 0)

        accessed = auditor.collect_accessed_keys()
        auditor.cleanup()

        self.assertIn("OPENAI_API_KEY", accessed)
        self.assertIn("GITHUB_TOKEN", accessed)
        self.assertIn("CUSTOM_BENIGN_VAR", accessed)

    def test_trace_observer_detects_runtime_secrets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            obs = TraceObserver(cwd=tmpdir)
            script = (
                "import ctypes\n"
                "libc = ctypes.CDLL(None)\n"
                "libc.getenv.argtypes = [ctypes.c_char_p]\n"
                "libc.getenv.restype = ctypes.c_char_p\n"
                "_ = libc.getenv(b'STRIPE_SECRET_KEY')\n"
            )
            fp, code = obs.trace_command(
                [sys.executable, "-c", script],
                agent_name="secret-accessor"
            )
            self.assertEqual(code, 0)
            self.assertIn("env:STRIPE_SECRET_KEY", fp.capabilities.secrets)


if __name__ == "__main__":
    unittest.main()
