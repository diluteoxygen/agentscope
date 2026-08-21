"""
Active Runtime Enforcement Engine for AgentScope.
Monitors agent syscalls in real time and terminates child process trees on baseline violations.
"""

from __future__ import annotations
import os
import re
import sys
import time
import signal
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import List, Set, Optional, Tuple, Dict, Any

from .models import CapabilityFingerprint, RiskLevel
from .observer import parse_strace_output, RE_PID_PREFIX, RE_OPEN, RE_EXEC, RE_CONNECT_IPV4
from .normalizer import Normalizer
from .auditor import EnvAuditor


@dataclass
class EnforcementViolation:
    pid: Optional[int]
    violation_type: str  # 'SECRET_ACCESS', 'UNAUTHORIZED_WRITE', 'UNAUTHORIZED_EXEC', 'UNAUTHORIZED_NETWORK'
    target: str
    raw_syscall: str
    action_taken: str  # 'TERMINATED'


class EnforcementEngine:
    """
    Enforces a capability baseline against live agent execution.
    """

    def __init__(
        self,
        baseline: CapabilityFingerprint,
        cwd: Optional[str] = None,
        strict_mode: bool = True
    ):
        self.baseline = baseline
        self.cwd = Path(cwd).resolve() if cwd else Path.cwd().resolve()
        self.strict_mode = strict_mode
        self.normalizer = Normalizer(str(self.cwd))

        # Build baseline whitelists
        caps = baseline.capabilities
        self.allowed_reads: Set[str] = set(caps.filesystem.read)
        self.allowed_writes: Set[str] = set(caps.filesystem.write)
        self.allowed_commands: Set[str] = set(caps.commands)
        self.allowed_network: Set[str] = set(caps.network)
        self.allowed_secrets: Set[str] = set(caps.secrets)

    def check_violation(self, line: str) -> Optional[EnforcementViolation]:
        """
        Inspects a single strace syscall line against the baseline profile.
        """
        clean_line = RE_PID_PREFIX.sub("", line.strip())

        # Check PID
        m_pid = re.match(r"^\[pid\s+(\d+)\]", line.strip())
        pid = int(m_pid.group(1)) if m_pid else None

        # 1. Inspect Execve (commands)
        m_exec = RE_EXEC.search(clean_line)
        if m_exec:
            cmd_path = m_exec.group(1)
            cmd_name = Path(cmd_path).name
            if self.allowed_commands and cmd_name not in self.allowed_commands:
                high_risk = {"curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "bash", "sh", "sudo"}
                if cmd_name in high_risk or self.strict_mode:
                    return EnforcementViolation(
                        pid=pid,
                        violation_type="UNAUTHORIZED_EXEC",
                        target=cmd_name,
                        raw_syscall=clean_line,
                        action_taken="TERMINATED"
                    )

        # 2. Inspect Open / Openat (files & secrets)
        m_open = RE_OPEN.search(clean_line)
        if m_open:
            path, flags = m_open.group(1), m_open.group(2)
            if not self.normalizer.is_system_noise(path):
                norm = self.normalizer.normalize_path(path)
                is_write = any(w in flags for w in ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"])

                # Check write permissions first
                if is_write:
                    if ".github/workflows" in norm or ".gitlab-ci" in norm:
                        if norm not in self.allowed_writes:
                            return EnforcementViolation(
                                pid=pid,
                                violation_type="UNAUTHORIZED_WRITE",
                                target=norm,
                                raw_syscall=clean_line,
                                action_taken="TERMINATED"
                            )

                # Check secret detection
                secrets = self.normalizer.detect_secrets(path)
                if secrets:
                    for s in secrets:
                        if s not in self.allowed_secrets:
                            # If it's a workflow write, categorize as UNAUTHORIZED_WRITE
                            if is_write and (".github" in norm or ".gitlab" in norm):
                                return EnforcementViolation(
                                    pid=pid,
                                    violation_type="UNAUTHORIZED_WRITE",
                                    target=norm,
                                    raw_syscall=clean_line,
                                    action_taken="TERMINATED"
                                )
                            return EnforcementViolation(
                                pid=pid,
                                violation_type="SECRET_ACCESS",
                                target=s,
                                raw_syscall=clean_line,
                                action_taken="TERMINATED"
                            )

        # 3. Inspect Network Connect
        m_conn = RE_CONNECT_IPV4.search(clean_line)
        if m_conn:
            port, ip = m_conn.group(1), m_conn.group(2)
            if ip not in ("127.0.0.1", "0.0.0.0"):
                dest = f"{ip}:{port}"
                if dest not in self.allowed_network and not any(ip in n for n in self.allowed_network):
                    return EnforcementViolation(
                        pid=pid,
                        violation_type="UNAUTHORIZED_NETWORK",
                        target=dest,
                        raw_syscall=clean_line,
                        action_taken="TERMINATED"
                    )

        return None

    def enforce_command(
        self,
        command: List[str],
        agent_name: str = "agent"
    ) -> Tuple[Optional[EnforcementViolation], int]:
        """
        Executes the command under active real-time syscall enforcement.
        Terminates the process group immediately on violation.
        """
        auditor = EnvAuditor()
        injected_env = auditor.get_injected_env()

        trace_cmd = [
            "strace",
            "-f",
            "-q",
            "-e", "trace=open,openat,creat,unlink,unlinkat,rename,renameat,renameat2,execve,execveat,connect,sendto,sendmsg,write",
            "-s", "1024",
            "--",
        ] + command

        violation: Optional[EnforcementViolation] = None
        exit_code = 0

        proc = subprocess.Popen(
            trace_cmd,
            cwd=str(self.cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            env=injected_env,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )

        try:
            while proc.poll() is None:
                if proc.stderr:
                    line = proc.stderr.readline()
                    if line:
                        v = self.check_violation(line)
                        if v:
                            violation = v
                            try:
                                if hasattr(os, "killpg"):
                                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                                else:
                                    proc.kill()
                            except Exception:
                                pass
                            break
                time.sleep(0.01)

            if not violation and proc.stderr:
                for line in proc.stderr.readlines():
                    v = self.check_violation(line)
                    if v:
                        violation = v
                        break

            proc.wait(timeout=2.0)
            exit_code = proc.returncode

        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        finally:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            auditor.cleanup()

        if violation:
            exit_code = 137  # Standard SIGKILL termination code

        return violation, exit_code
