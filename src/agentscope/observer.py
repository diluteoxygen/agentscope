"""
Trace observer for capturing process execution and syscalls on Linux.
"""

from __future__ import annotations
import codecs
import os
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set, Optional, Tuple, Dict, Any

from .models import CapabilityFingerprint, RunMetadata
from .normalizer import Normalizer
from .sni import extract_tls_sni
from .auditor import EnvAuditor

# Regex patterns for strace parsing
RE_PID_PREFIX = re.compile(r"^(?:\[pid\s+\d+\]|\d+)\s+")

RE_OPEN = re.compile(r'(?:open|openat|openat2)\((?:[^,]*,)?\s*"([^"]+)",\s*([^,\)]+)')
RE_CREAT = re.compile(r'creat\("([^"]+)"')
RE_UNLINK = re.compile(r'unlink(?:at)?\((?:[^,]*,)?\s*"([^"]+)"')
RE_RENAME = re.compile(r'rename(?:at|at2)?\((?:[^,]*,)?\s*"([^"]+)",\s*(?:[^,]*,)?\s*"([^"]+)"')
RE_EXEC = re.compile(r'execve(?:at)?\((?:[^,]*,)?\s*"([^"]+)"')

RE_CONNECT_IPV4 = re.compile(
    r'connect\([^,]*,\s*\{sa_family=AF_INET,\s*sin_port=htons\(([0-9]+)\),\s*sin_addr=inet_addr\("([^"]+)"\)'
)
RE_CONNECT_IPV6 = re.compile(
    r'connect\([^,]*,\s*\{sa_family=AF_INET6,\s*sin6_port=htons\(([0-9]+)\),.*?"([^"]+)"'
)

RE_SEND_BUFFER = re.compile(r'(?:sendto|sendmsg|write)\([0-9]+,\s*"([^"]+)"')


def parse_buffer_bytes(escaped_str: str) -> bytes:
    """
    Decodes a C-escaped buffer string from strace into raw bytes.
    """
    try:
        return codecs.escape_decode(escaped_str.encode("utf-8"))[0]
    except Exception:
        return escaped_str.encode("utf-8", errors="replace")


def parse_strace_output(
    lines: List[str]
) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
    """
    Parses strace output lines into raw sets of reads, writes, commands, and network endpoints.
    """
    raw_reads: Set[str] = set()
    raw_writes: Set[str] = set()
    raw_commands: Set[str] = set()
    raw_network: Set[str] = set()

    for raw_line in lines:
        line = RE_PID_PREFIX.sub("", raw_line.strip())

        # Execve / Execveat
        m_exec = RE_EXEC.search(line)
        if m_exec:
            raw_commands.add(m_exec.group(1))

        # Open / Openat
        m_open = RE_OPEN.search(line)
        if m_open:
            path, flags = m_open.group(1), m_open.group(2)
            if any(w in flags for w in ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"]):
                raw_writes.add(path)
            else:
                raw_reads.add(path)

        # Creat
        m_creat = RE_CREAT.search(line)
        if m_creat:
            raw_writes.add(m_creat.group(1))

        # Unlink / Unlinkat
        m_unlink = RE_UNLINK.search(line)
        if m_unlink:
            raw_writes.add(m_unlink.group(1))

        # Rename / Renameat
        m_rename = RE_RENAME.search(line)
        if m_rename:
            raw_reads.add(m_rename.group(1))
            raw_writes.add(m_rename.group(2))

        # Connect IPv4
        m_conn4 = RE_CONNECT_IPV4.search(line)
        if m_conn4:
            port, ip = m_conn4.group(1), m_conn4.group(2)
            if ip not in ("127.0.0.1", "0.0.0.0"):
                try:
                    host = socket.gethostbyaddr(ip)[0]
                    raw_network.add(f"{host}:{port}")
                except Exception:
                    raw_network.add(f"{ip}:{port}")

        # Connect IPv6
        m_conn6 = RE_CONNECT_IPV6.search(line)
        if m_conn6:
            port, ip = m_conn6.group(1), m_conn6.group(2)
            if ip not in ("::1", "::"):
                try:
                    host = socket.gethostbyaddr(ip)[0]
                    raw_network.add(f"{host}:{port}")
                except Exception:
                    raw_network.add(f"{ip}:{port}")

        # TLS Client Hello SNI sniffing from send/write buffer
        m_send = RE_SEND_BUFFER.search(line)
        if m_send and ("\\x16" in m_send.group(1) or "\\026" in m_send.group(1)):
            raw_buf = parse_buffer_bytes(m_send.group(1))
            sni_host = extract_tls_sni(raw_buf)
            if sni_host:
                raw_network.add(f"{sni_host}:443")

    return raw_reads, raw_writes, raw_commands, raw_network


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
        Runs the command under strace observation and in-process env auditing, returning (CapabilityFingerprint, exit_code).
        """
        start_time = time.time()
        timestamp = datetime.now(timezone.utc).isoformat()

        raw_reads: Set[str] = set()
        raw_writes: Set[str] = set()
        raw_commands: Set[str] = set()
        raw_network: Set[str] = set()
        raw_env: Set[str] = set()

        if command:
            raw_commands.add(command[0])

        auditor = EnvAuditor()
        injected_env = auditor.get_injected_env()

        if self.has_strace:
            trace_cmd = [
                "strace",
                "-f",
                "-q",
                "-e", "trace=open,openat,creat,unlink,unlinkat,rename,renameat,renameat2,execve,execveat,connect,sendto,sendmsg,write",
                "-s", "1024",
                "--",
            ] + command

            proc = subprocess.Popen(
                trace_cmd,
                cwd=str(self.cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                env=injected_env,
            )

            stdout, stderr = proc.communicate()
            exit_code = proc.returncode

            parsed_reads, parsed_writes, parsed_cmds, parsed_net = parse_strace_output(
                stderr.splitlines()
            )
            raw_reads.update(parsed_reads)
            raw_writes.update(parsed_writes)
            raw_commands.update(parsed_cmds)
            raw_network.update(parsed_net)
        else:
            proc = subprocess.run(
                command,
                cwd=str(self.cwd),
                capture_output=True,
                text=True,
                env=injected_env,
            )
            exit_code = proc.returncode

        duration_ms = int((time.time() - start_time) * 1000)

        # Collect in-process accessed env vars
        accessed_env_keys = auditor.collect_accessed_keys()
        auditor.cleanup()
        raw_env.update(accessed_env_keys)

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
