"""
Git hook integration for automated authority verification before commits and pushes.
"""

from __future__ import annotations
import os
import stat
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple


HOOK_SCRIPT_TEMPLATE = """#!/bin/sh
# AgentScope Git Safety Hook (Auto-generated)
# Prevents committing or pushing unverified AI agent capability escalations.

if [ "$AGENTSCOPE_SKIP_HOOK" = "1" ] || [ "$AGENTSCOPE_SKIP_VERIFY" = "1" ]; then
    exit 0
fi

if [ ! -f ".agent/authority-baseline.json" ]; then
    exit 0
fi

if [ -f "agentscope.json" ]; then
    echo "[agentscope-hook] Verifying agent authority against baseline..."
    if command -v agentscope >/dev/null 2>&1; then
        agentscope verify --baseline .agent/authority-baseline.json --candidate agentscope.json
    else
        python3 -m agentscope.cli verify --baseline .agent/authority-baseline.json --candidate agentscope.json
    fi
    
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo ""
        echo "❌ [agentscope-hook] BLOCKED: Unauthorized agent capability escalation detected!"
        echo "   • Inspect delta: agentscope diff .agent/authority-baseline.json agentscope.json"
        echo "   • Accept into baseline: agentscope baseline"
        echo "   • Temporary bypass: export AGENTSCOPE_SKIP_HOOK=1"
        exit 1
    fi
fi

exit 0
"""


def find_git_hooks_dir(repo_dir: Optional[str] = None) -> Optional[Path]:
    """
    Locates the .git/hooks directory for the target or current repository.
    """
    root = Path(repo_dir).resolve() if repo_dir else Path.cwd().resolve()
    git_dir = root / ".git"
    
    if git_dir.is_file():
        # Handle git worktrees or submodules (where .git is a file referencing gitdir)
        try:
            content = git_dir.read_text().strip()
            if content.startswith("gitdir:"):
                target = content.split(":", 1)[1].strip()
                git_dir = (root / target).resolve()
        except Exception:
            return None

    if not git_dir.exists():
        return None

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    return hooks_dir


def install_git_hooks(
    repo_dir: Optional[str] = None,
    hook_types: Optional[List[str]] = None,
    force: bool = False
) -> Dict[str, bool]:
    """
    Installs AgentScope verification scripts into .git/hooks/<hook_type>.
    """
    hooks_dir = find_git_hooks_dir(repo_dir)
    if not hooks_dir:
        raise FileNotFoundError("Could not find .git repository root.")

    target_hooks = hook_types or ["pre-commit", "pre-push"]
    results: Dict[str, bool] = {}

    for hook_name in target_hooks:
        hook_path = hooks_dir / hook_name
        if hook_path.exists() and not force:
            # Check if already installed
            existing = hook_path.read_text()
            if "agentscope-hook" in existing:
                results[hook_name] = True
                continue

        hook_path.write_text(HOOK_SCRIPT_TEMPLATE)
        # Make executable (chmod +x)
        current_stat = hook_path.stat().st_mode
        hook_path.chmod(current_stat | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        results[hook_name] = True

    return results


def uninstall_git_hooks(
    repo_dir: Optional[str] = None,
    hook_types: Optional[List[str]] = None
) -> Dict[str, bool]:
    """
    Removes AgentScope hook scripts from .git/hooks/<hook_type>.
    """
    hooks_dir = find_git_hooks_dir(repo_dir)
    if not hooks_dir:
        raise FileNotFoundError("Could not find .git repository root.")

    target_hooks = hook_types or ["pre-commit", "pre-push"]
    results: Dict[str, bool] = {}

    for hook_name in target_hooks:
        hook_path = hooks_dir / hook_name
        if hook_path.exists():
            content = hook_path.read_text()
            if "agentscope-hook" in content:
                hook_path.unlink()
                results[hook_name] = True
            else:
                results[hook_name] = False
        else:
            results[hook_name] = False

    return results


def check_git_hooks_status(
    repo_dir: Optional[str] = None,
    hook_types: Optional[List[str]] = None
) -> Dict[str, bool]:
    """
    Checks if AgentScope hooks are currently installed.
    """
    hooks_dir = find_git_hooks_dir(repo_dir)
    if not hooks_dir:
        return {}

    target_hooks = hook_types or ["pre-commit", "pre-push"]
    status_map: Dict[str, bool] = {}

    for hook_name in target_hooks:
        hook_path = hooks_dir / hook_name
        if hook_path.exists() and "agentscope-hook" in hook_path.read_text():
            status_map[hook_name] = True
        else:
            status_map[hook_name] = False

    return status_map
