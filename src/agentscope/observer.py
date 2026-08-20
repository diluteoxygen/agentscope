"""
Trace observer for capturing process execution and syscalls on Linux.
"""

from __future__ import annotations
import os
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set, Optional, Tuple

from .models import CapabilityFingerprint, RunMetadata
from .normalizer import Normalizer

# Regex parsers for common strace outputs
RE_OPEN = re.compile(r'(?:open|openat)\([^,]*,\s*"([^"]+)",\s*([^,\)]+)')
RE_CREAT = re.compile(r'creat\("([^"]+)"')
RE_UNLINK = re.compile(r'unlink(?:at)?\([^,]*,\s*"([^"]+)"')
RE_EXEC = re.compile(r'execve(?:at)?\([^,]*,\s*"([^"]+)"')
RE_CONNECT = re.compile(r'connect\([^,]*,\s*\{sa_family=AF_INET(?:6)?,\s*sin(?:6)?_port=htons\(([0-9]+)\),\s*sin(?:6)?_addr=inet_addr\("([^"]+)"\)')


class TraceObserver:
    def __init__(self, cwd: Optional[str] = None):
        self.cwd = Path(cwd).resolve() if cwd else Path.cwd().resolve()
        self.normalizer = Normalizer(str(self.cwd))
        self.has_strace = shutil.which("strace") is not None

    def trace_command(
        self,
        command: List[str],
        agent_name: str = "agent"
    ) -> Tuple[CapabilityFingerprint, int]:
        """
        Runs the command under strace observation and returns (CapabilityFingerprint, exit_code).
        """
        start_time = time.time()
        timestamp = datetime.now(timezone.utc).isoformat()

        raw_reads: Set[str] = set()
        raw_writes: Set[str] = set()
        raw_commands: Set[str] = set()
        raw_network: Set[str] = set()
        raw_env: Set[str] = set()

        # Add initial command
        if command:
            raw_commands.add(command[0])

        if self.has_strace:
            trace_cmd = [
                "strace",
                "-f",
                "-q",
                "-e", "trace=open,openat,creat,unlink,unlinkat,execve,execveat,connect",
                "-s", "512",
                "--",
            ] + command

            proc = subprocess.Popen(
                trace_cmd,
                cwd=str(self.cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace"
            )

            stdout, stderr = proc.communicate()
            exit_code = proc.returncode

            # Parse strace log from stderr
            for line in stderr.splitlines():
                # Check execve
                m_exec = RE_EXEC.search(line)
                if m_exec:
                    raw_commands.add(m_exec.group(1))

                # Check open/openat
                m_open = RE_OPEN.search(line)
                if m_open:
                    path, flags = m_open.group(1), m_open.group(2)
                    if any(w in flags for w in ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"]):
                        raw_writes.add(path)
                    else:
                        raw_reads.add(path)

                # Check creat / unlink
                m_creat = RE_CREAT.search(line)
                if m_creat:
                    raw_writes.add(m_creat.group(1))

                m_unlink = RE_UNLINK.search(line)
                if m_unlink:
                    raw_writes.add(m_unlink.group(1))

                # Check connect
                m_conn = RE_CONNECT.search(line)
                if m_conn:
                    port, ip = m_conn.group(1), m_conn.group(2)
                    if ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                        # Try hostname resolution
                        try:
                            host = socket.gethostbyaddr(ip)[0]
                            raw_network.add(f"{host}:{port}")
                        except Exception:
                            raw_network.add(f"{ip}:{port}")
        else:
            # Fallback direct execution if strace is missing
            proc = subprocess.run(
                command,
                cwd=str(self.cwd),
                capture_output=True,
                text=True
            )
            exit_code = proc.returncode

        duration_ms = int((time.time() - start_time) * 1000)

        # Inspect environment variables currently available in the session
        for env_k in os.environ.keys():
            raw_env.add(env_k)

        capabilities = self.normalizer.build_capabilities(
            raw_reads=raw_reads,
            raw_writes=raw_writes,
            raw_commands=raw_commands,
            raw_network=raw_network,
            raw_env_accessed=raw_env,
        )

        metadata = RunMetadata(
            agent=agent_name,
            command=command,
            timestamp=timestamp,
            duration_ms=duration_ms,
            exit_code=exit_code,
            cwd=str(self.cwd),
            hostname=socket.gethostname(),
        )

        fingerprint = CapabilityFingerprint(
            schema_version="1.0",
            metadata=metadata,
            capabilities=capabilities,
        )

        return fingerprint, exit_code
