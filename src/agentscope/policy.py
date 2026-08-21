"""
Agent Sandbox Policy Exporter for AgentScope.
Converts verified capability fingerprints into hardened runtime isolation rules:
- Docker security run flags
- Docker / Kubernetes Seccomp JSON profiles
- Bubblewrap (bwrap) sandbox arguments
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from .models import CapabilityFingerprint


def export_docker_flags(fp: CapabilityFingerprint) -> List[str]:
    """
    Generates recommended Docker confinement flags based on the capability fingerprint.
    """
    caps = fp.capabilities
    flags = [
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
    ]

    # Network isolation
    if not caps.network:
        flags.append("--network=none")
    else:
        flags.append("--network=bridge")

    # Read-only root filesystem recommendation
    flags.append("--read-only")

    # Mount temporary write paths
    for w in caps.filesystem.write:
        if w.startswith("./"):
            rel_dir = str(Path(w).parent)
            flags.append(f"--tmpfs /workspace/{rel_dir.lstrip('./')}:rw,noexec,nosuid")

    return flags


def export_seccomp_profile(fp: CapabilityFingerprint) -> Dict[str, Any]:
    """
    Generates a hardened Seccomp JSON security profile restricting allowed syscalls.
    """
    caps = fp.capabilities
    allowed_syscalls = [
        "read", "write", "open", "openat", "close", "stat", "fstat", "lstat",
        "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction",
        "rt_sigprocmask", "ioctl", "access", "pipe", "select", "sched_yield",
        "getpid", "getuid", "getgid", "geteuid", "getegid", "exit_group"
    ]

    if caps.commands:
        allowed_syscalls.extend(["execve", "execveat", "clone", "clone3", "fork", "vfork", "wait4", "pipe2"])

    if caps.network:
        allowed_syscalls.extend(["socket", "connect", "sendto", "recvfrom", "sendmsg", "recvmsg", "getsockopt", "setsockopt"])

    profile = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": [
            "SCMP_ARCH_X86_64",
            "SCMP_ARCH_X86",
            "SCMP_ARCH_AARCH64"
        ],
        "syscalls": [
            {
                "names": sorted(list(set(allowed_syscalls))),
                "action": "SCMP_ACT_ALLOW",
                "args": [],
                "comment": "Allowed by AgentScope Authority Baseline"
            }
        ]
    }
    return profile


def export_bwrap_command(fp: CapabilityFingerprint, base_command: Optional[List[str]] = None) -> List[str]:
    """
    Generates Bubblewrap (bwrap) sandbox isolation arguments.
    """
    caps = fp.capabilities
    bwrap_cmd = [
        "bwrap",
        "--ro-bind", "/", "/",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
    ]

    if not caps.network:
        bwrap_cmd.append("--unshare-net")

    for w in caps.filesystem.write:
        if w.startswith("./"):
            bwrap_cmd.extend(["--bind", w, w])

    if base_command:
        bwrap_cmd.extend(["--"] + base_command)

    return bwrap_cmd
