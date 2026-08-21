"""
Dedicated agent wrappers and launchers for popular coding assistants.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class AgentProfile:
    name: str
    description: str
    default_executable: str
    known_safe_network: List[str]
    sensitive_env_keys: List[str]


AGENT_PROFILES: Dict[str, AgentProfile] = {
    "antigravity": AgentProfile(
        name="antigravity",
        description="Google Antigravity (AGY) Autonomous Development Agent",
        default_executable="agy",
        known_safe_network=[
            "generativelanguage.googleapis.com:443",
            "oauth2.googleapis.com:443",
            "antigravity.google:443",
            "cloudresourcemanager.googleapis.com:443",
        ],
        sensitive_env_keys=[
            "GEMINI_API_KEY",
            "GOOGLE_API_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "ANTIGRAVITY_APP_DATA",
        ],
    ),
    "agy": AgentProfile(
        name="agy",
        description="Google Antigravity CLI",
        default_executable="agy",
        known_safe_network=[
            "generativelanguage.googleapis.com:443",
            "oauth2.googleapis.com:443",
            "antigravity.google:443",
        ],
        sensitive_env_keys=[
            "GEMINI_API_KEY",
            "GOOGLE_API_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ],
    ),
    "claude": AgentProfile(
        name="claude",
        description="Anthropic Claude Code CLI",
        default_executable="claude",
        known_safe_network=["api.anthropic.com:443", "statsig.anthropic.com:443"],
        sensitive_env_keys=["ANTHROPIC_API_KEY", "CLAUDE_CODE_TOKEN"],
    ),
    "aider": AgentProfile(
        name="aider",
        description="Aider AI pair programmer",
        default_executable="aider",
        known_safe_network=["api.openai.com:443", "api.anthropic.com:443", "openrouter.ai:443"],
        sensitive_env_keys=["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"],
    ),
    "cursor": AgentProfile(
        name="cursor",
        description="Cursor IDE background agent",
        default_executable="cursor",
        known_safe_network=["api2.cursor.sh:443", "repo42.cursor.sh:443"],
        sensitive_env_keys=["CURSOR_AUTH_TOKEN"],
    ),
    "opencode": AgentProfile(
        name="opencode",
        description="OpenCode autonomous agent",
        default_executable="opencode",
        known_safe_network=["api.github.com:443"],
        sensitive_env_keys=["GITHUB_TOKEN"],
    ),
}


def get_agent_profile(name: str) -> Optional[AgentProfile]:
    """
    Returns the known agent profile or None if generic.
    """
    return AGENT_PROFILES.get(name.lower())
