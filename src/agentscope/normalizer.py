"""
Normalizer for transforming low-level kernel syscall events into canonical capabilities.
"""

from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Set, List, Optional, Tuple
from .models import Capabilities, FilesystemCapabilities

# System noise paths to exclude from general authority fingerprinting
SYSTEM_NOISE_PATTERNS = [
    re.compile(r"^/lib(/|$)"),
    re.compile(r"^/usr/lib(/|$)"),
    re.compile(r"^/usr/share/locale(/|$)"),
    re.compile(r"^/etc/ld\.so"),
    re.compile(r"^/etc/fonts(/|$)"),
    re.compile(r"^/dev/(null|urandom|zero|tty|pts)"),
    re.compile(r"^/proc/(self|$$|[0-9]+)/(stat|status|cmdline|environ|maps|fd)"),
]

# Sensitive paths and env patterns
SENSITIVE_PATH_PATTERNS = [
    (re.compile(r"(\.ssh/|\.ssh$)"), "SSH Keys & Configuration"),
    (re.compile(r"(\.aws/|\.aws$)"), "AWS Credentials"),
    (re.compile(r"(\.config/gh/|\.git-credentials)"), "Git / GitHub Credentials"),
    (re.compile(r"(\.env$|\.env\.)"), "Environment Secrets File"),
    (re.compile(r"(\.kube/config)"), "Kubernetes Credentials"),
    (re.compile(r"(\.gnupg/)"), "GPG Keyring"),
    (re.compile(r"(\.github/workflows/)"), "CI/CD Workflow Definitions"),
]

SENSITIVE_ENV_VARS = {
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "STRIPE_API_KEY",
    "DATABASE_URL",
    "SSH_AUTH_SOCK",
}


class Normalizer:
    def __init__(self, cwd: Optional[str] = None):
        self.cwd = Path(cwd).resolve() if cwd else Path.cwd().resolve()
        self.home = Path.home().resolve()

    def is_system_noise(self, path_str: str) -> bool:
        for pat in SYSTEM_NOISE_PATTERNS:
            if pat.search(path_str):
                return True
        return False

    def normalize_path(self, raw_path: str) -> str:
        try:
            p = Path(raw_path)
            if not p.is_absolute():
                p = (self.cwd / p).resolve()
            else:
                p = p.resolve()
        except Exception:
            return raw_path

        p_str = str(p)
        cwd_str = str(self.cwd)
        home_str = str(self.home)

        if p_str == cwd_str:
            return "."
        elif p_str.startswith(cwd_str + "/"):
            return "./" + str(p.relative_to(self.cwd))
        elif p_str.startswith(home_str + "/"):
            return "~/" + str(p.relative_to(self.home))
        elif p_str == home_str:
            return "~"
        else:
            return p_str

    def detect_secrets(self, path: str, env_vars: Optional[List[str]] = None) -> List[str]:
        found = []
        for pattern, label in SENSITIVE_PATH_PATTERNS:
            if pattern.search(path):
                found.append(f"{self.normalize_path(path)} ({label})")
        if env_vars:
            for env in env_vars:
                if env in SENSITIVE_ENV_VARS:
                    found.append(f"env:{env}")
        return found

    def build_capabilities(
        self,
        raw_reads: Set[str],
        raw_writes: Set[str],
        raw_commands: Set[str],
        raw_network: Set[str],
        raw_env_accessed: Optional[Set[str]] = None,
    ) -> Capabilities:
        reads: Set[str] = set()
        writes: Set[str] = set()
        secrets: Set[str] = set()

        for r in raw_reads:
            if not self.is_system_noise(r):
                norm = self.normalize_path(r)
                reads.add(norm)
                for s in self.detect_secrets(r):
                    secrets.add(s)

        for w in raw_writes:
            if not self.is_system_noise(w):
                norm = self.normalize_path(w)
                writes.add(norm)
                for s in self.detect_secrets(w):
                    secrets.add(s)

        commands: Set[str] = set()
        for cmd in raw_commands:
            cmd_name = Path(cmd).name
            commands.add(cmd_name)

        network: Set[str] = set()
        for dest in raw_network:
            dest_clean = dest.strip()
            if dest_clean:
                network.add(dest_clean)

        if raw_env_accessed:
            for env in raw_env_accessed:
                if env in SENSITIVE_ENV_VARS:
                    secrets.add(f"env:{env}")

        caps = Capabilities(
            filesystem=FilesystemCapabilities(
                read=sorted(list(reads)),
                write=sorted(list(writes))
            ),
            commands=sorted(list(commands)),
            network=sorted(list(network)),
            secrets=sorted(list(secrets)),
        )
        return caps
