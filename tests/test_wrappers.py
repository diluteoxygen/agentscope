"""
Unit tests for agent profiles and launchers.
"""

import unittest
from agentscope.wrappers import AGENT_PROFILES, get_agent_profile


class TestWrappers(unittest.TestCase):
    def test_known_agent_profiles(self):
        claude = get_agent_profile("claude")
        self.assertIsNotNone(claude)
        self.assertEqual(claude.default_executable, "claude")
        self.assertIn("ANTHROPIC_API_KEY", claude.sensitive_env_keys)

        aider = get_agent_profile("aider")
        self.assertIsNotNone(aider)
        self.assertEqual(aider.default_executable, "aider")

        cursor = get_agent_profile("cursor")
        self.assertIsNotNone(cursor)

    def test_unknown_agent_profile(self):
        unknown = get_agent_profile("custom_unknown_agent_xyz")
        self.assertIsNone(unknown)


if __name__ == "__main__":
    unittest.main()
