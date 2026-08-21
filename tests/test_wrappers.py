"""
Unit tests for agent profiles and launchers.
"""

import unittest
from agentscope.wrappers import AGENT_PROFILES, get_agent_profile


class TestWrappers(unittest.TestCase):
    def test_known_agent_profiles(self):
        # Antigravity
        antigravity = get_agent_profile("antigravity")
        self.assertIsNotNone(antigravity)
        self.assertEqual(antigravity.default_executable, "agy")
        self.assertIn("GEMINI_API_KEY", antigravity.sensitive_env_keys)
        self.assertIn("generativelanguage.googleapis.com:443", antigravity.known_safe_network)

        # AGY CLI
        agy = get_agent_profile("agy")
        self.assertIsNotNone(agy)
        self.assertEqual(agy.default_executable, "agy")
        self.assertIn("GOOGLE_API_KEY", agy.sensitive_env_keys)

        # Claude
        claude = get_agent_profile("claude")
        self.assertIsNotNone(claude)
        self.assertEqual(claude.default_executable, "claude")
        self.assertIn("ANTHROPIC_API_KEY", claude.sensitive_env_keys)

        # Aider
        aider = get_agent_profile("aider")
        self.assertIsNotNone(aider)
        self.assertEqual(aider.default_executable, "aider")

        # Cursor
        cursor = get_agent_profile("cursor")
        self.assertIsNotNone(cursor)

    def test_unknown_agent_profile(self):
        unknown = get_agent_profile("custom_unknown_agent_xyz")
        self.assertIsNone(unknown)


if __name__ == "__main__":
    unittest.main()
