"""
Normalizer for transforming low-level kernel syscall events into canonical capabilities.
"""

from __future__ import annotations
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Set, List, Optional, Tuple, Dict
from .models import Capabilities, FilesystemCapabilities

# System noise paths to exclude from general authority fingerprinting
SYSTEM_NOISE_PATTERNS = [
    re.compile(r"^/lib(?:64)?(/|$)"),
    re.compile(r"^/usr/lib(?:64)?(/|$)"),
    re.compile(r"^/usr/local/lib/python[0-9.]+(/|$)"),
    re.compile(r"^/opt/hostedtoolcache/Python(/|$)"),
    re.compile(r"^/usr/share/(?:locale|zoneinfo|mime|doc)(/|$)"),
    re.compile(r"^/etc/(?:ld\.so|fonts|localtime|timezone|magic|mime\.types)"),
    re.compile(r"^/dev/(?:null|urandom|random|zero|tty|pts)"),
    re.compile(r"^/proc/(?:self|$$|[0-9]+)/(?:stat|status|cmdline|environ|maps|fd|task)"),
    re.compile(r"^/proc/(?:cpuinfo|meminfo|version|sys)"),
    re.compile(r"^/sys/(?:devices|bus|class|fs)(/|$)"),
    re.compile(r"(?:^|/)\.agentscope_env_[^/]+\.log$"),
]

# Sensitive paths and classifications
SENSITIVE_PATH_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(\.ssh/|\.ssh$|id_rsa|id_ed25519)"), "SSH Keys & Configuration"),
    (re.compile(r"(\.aws/|\.aws$)"), "AWS Credentials"),
    (re.compile(r"(\.azure/|\.gcp/|\.config/gcloud/)"), "Cloud Provider Credentials"),
    (re.compile(r"(\.config/gh/|\.git-credentials|\.netrc)"), "Git / GitHub Credentials"),
    (re.compile(r"(\.npmrc|\.pypirc)"), "Package Registry Credentials"),
    (re.compile(r"(\.env$|\.env\.)"), "Environment Secrets File"),
    (re.compile(r"(\.kube/config|\.docker/config\.json)"), "Infrastructure & Container Credentials"),
    (re.compile(r"(\.gnupg/)"), "GPG Keyring"),
    (re.compile(r"(\.github/workflows/|\.gitlab-ci\.yml|\.circleci/)"), "CI/CD Workflow Definitions"),
    (re.compile(r"\.(pem|key)$"), "Private Cryptographic Key"),
]

SENSITIVE_ENV_VARS: Set[str] = {
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "ANTIGRAVITY_APP_DATA",
    "STRIPE_API_KEY",
    "STRIPE_SECRET_KEY",
    "SLACK_BOT_TOKEN",
    "DISCORD_TOKEN",
    "DATABASE_URL",
    "POSTGRES_PASSWORD",
    "REDIS_URL",
    "SSH_AUTH_SOCK",
}



def coalesce_paths(paths: List[str], threshold: int = 5) -> List[str]:
    """
    Coalesces a list of file paths into directory globs when file count in a directory reaches threshold.
    """
    if threshold <= 1:
        return sorted(list(set(paths)))

    dir_groups: Dict[str, List[str]] = defaultdict(list)
    top_level_files: List[str] = []

    for p in paths:
        if "/" in p:
            parent_dir = str(Path(p).parent)
            if p.startswith("./") and not parent_dir.startswith("./"):
                parent_dir = "./" + parent_dir
            dir_groups[parent_dir].append(p)
        else:
            top_level_files.append(p)

    result_paths: Set[str] = set(top_level_files)

    for parent_dir, file_list in dir_groups.items():
        if len(file_list) >= threshold:
            glob_path = f"{parent_dir}/**"
            result_paths.add(glob_path)
        else:
            result_paths.update(file_list)

    return sorted(list(result_paths))


class Normalizer:
    def __init__(self, cwd: Optional[str] = None, coalesce_threshold: Optional[int] = None):
        self.cwd = Path(cwd).resolve() if cwd else Path.cwd().resolve()
        self.home = Path.home().resolve()
        self.coalesce_threshold = coalesce_threshold

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
            if cmd_name:
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

        read_list = sorted(list(reads))
        write_list = sorted(list(writes))

        if self.coalesce_threshold and self.coalesce_threshold > 1:
            read_list = coalesce_paths(read_list, threshold=self.coalesce_threshold)
            write_list = coalesce_paths(write_list, threshold=self.coalesce_threshold)

        caps = Capabilities(
            filesystem=FilesystemCapabilities(
                read=read_list,
                write=write_list
            ),
            commands=sorted(list(commands)),
            network=sorted(list(network)),
            secrets=sorted(list(secrets)),
        )
        return caps
