"""
Live Terminal UI (TUI) Monitor for real-time AI agent authority observation.
Uses standard ANSI terminal escape sequences for zero-dependency live status rendering.
"""

from __future__ import annotations
import os
import sys
import time
import subprocess
import shutil
from typing import List, Set, Optional, Tuple
from pathlib import Path

from .models import CapabilityFingerprint, Capabilities, FilesystemCapabilities, RiskLevel
from .observer import parse_strace_output
from .normalizer import Normalizer
from .auditor import EnvAuditor


class TerminalMonitor:
    """
    Renders a live terminal dashboard during agent execution.
    """

    def __init__(self, agent_name: str = "agent"):
        self.agent_name = agent_name
        self.reads: Set[str] = set()
        self.writes: Set[str] = set()
        self.commands: Set[str] = set()
        self.network: Set[str] = set()
        self.secrets: Set[str] = set()
        self.current_risk = RiskLevel.LOW
        self.events: List[str] = []
        self.normalizer = Normalizer()

    def update_with_line(self, raw_line: str) -> None:
        """
        Parses a single strace event line and updates the monitor state.
        """
        r, w, c, n = parse_strace_output([raw_line])
        for path in r:
            if not self.normalizer.is_system_noise(path):
                norm = self.normalizer.normalize_path(path)
                if norm not in self.reads:
                    self.reads.add(norm)
                    self._add_event(f"READ: {norm}")
                    for s in self.normalizer.detect_secrets(path):
                        self.secrets.add(s)
                        self._add_event(f"SECRET ACCESSED: {s}")

        for path in w:
            if not self.normalizer.is_system_noise(path):
                norm = self.normalizer.normalize_path(path)
                if norm not in self.writes:
                    self.writes.add(norm)
                    self._add_event(f"WRITE: {norm}")
                    for s in self.normalizer.detect_secrets(path):
                        self.secrets.add(s)
                        self._add_event(f"SECRET TOUCHED: {s}")

        for cmd in c:
            cmd_name = Path(cmd).name
            if cmd_name and cmd_name not in self.commands:
                self.commands.add(cmd_name)
                self._add_event(f"EXEC: {cmd_name}")

        for dest in n:
            dest_clean = dest.strip()
            if dest_clean and dest_clean not in self.network:
                self.network.add(dest_clean)
                self._add_event(f"NET: {dest_clean}")

        # Update Risk Gauge
        if self.secrets:
            self.current_risk = RiskLevel.CRITICAL
        elif any(".github" in path for path in self.writes):
            self.current_risk = RiskLevel.HIGH
        elif self.network:
            self.current_risk = RiskLevel.MEDIUM

    def _add_event(self, msg: str) -> None:
        self.events.append(msg)
        if len(self.events) > 8:
            self.events.pop(0)

    def render_frame(self, elapsed_sec: float) -> str:
        """
        Generates an ASCII frame summarizing current authority metrics and live event log.
        """
        risk_color = "\033[92m" if self.current_risk == RiskLevel.LOW else (
            "\033[93m" if self.current_risk == RiskLevel.MEDIUM else "\033[91m"
        )
        reset = "\033[0m"
        bold = "\033[1m"
        cyan = "\033[96m"

        lines = [
            f"{bold}┌─ AGENTSCOPE REAL-TIME AUTHORITY MONITOR ──────────────────────────────┐{reset}",
            f"│ Agent: {cyan}{self.agent_name:<16}{reset} Elapsed: {elapsed_sec:>5.1f}s   Risk: {risk_color}{bold}{self.current_risk.value:<10}{reset}     │",
            f"├────────────────────────────────────────────────────────────────────────┤",
            f"│ Files Read: {len(self.reads):<4}  Files Written: {len(self.writes):<4}  Commands: {len(self.commands):<4}  Sockets: {len(self.network):<4} │",
            f"│ Secrets Touched: {risk_color}{len(self.secrets):<4}{reset}                                                │",
            f"├─ LIVE EVENT STREAM ──────────────────────────────────────────────────┤",
        ]

        if not self.events:
            lines.append("│ (waiting for activity...)                                              │")
        else:
            for ev in self.events[-5:]:
                truncated = ev[:68]
                lines.append(f"│ • {truncated:<68} │")

        lines.append(f"└────────────────────────────────────────────────────────────────────────┘")
        return "\n".join(lines)


def run_live_monitor(command: List[str], agent_name: str = "agent") -> Tuple[CapabilityFingerprint, int]:
    """
    Executes a command with a live terminal UI dashboard and generates a capability fingerprint.
    """
    monitor = TerminalMonitor(agent_name=agent_name)
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

    start_time = time.time()
    
    # Hide cursor
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()

    try:
        proc = subprocess.Popen(
            trace_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            env=injected_env,
        )

        while proc.poll() is None:
            # Non-blocking or line-by-line read
            if proc.stderr:
                line = proc.stderr.readline()
                if line:
                    monitor.update_with_line(line)

            elapsed = time.time() - start_time
            frame = monitor.render_frame(elapsed)
            
            # Clear and redraw frame
            sys.stdout.write("\033[H\033[J" + frame + "\n")
            sys.stdout.flush()
            time.sleep(0.05)

        # Read remaining stderr
        if proc.stderr:
            for line in proc.stderr.readlines():
                monitor.update_with_line(line)

        exit_code = proc.returncode

    finally:
        # Show cursor
        sys.stdout.write("\033[?25h\n")
        sys.stdout.flush()

    # Collect accessed env keys
    accessed_env = auditor.collect_accessed_keys()
    auditor.cleanup()

    caps = monitor.normalizer.build_capabilities(
        raw_reads=monitor.reads,
        raw_writes=monitor.writes,
        raw_commands=monitor.commands,
        raw_network=monitor.network,
        raw_env_accessed=accessed_env,
    )

    from datetime import datetime, timezone
    import socket
    from .models import RunMetadata

    metadata = RunMetadata(
        agent=agent_name,
        command=command,
        timestamp=datetime.now(timezone.utc).isoformat(),
        duration_ms=int((time.time() - start_time) * 1000),
        exit_code=exit_code,
        cwd=os.getcwd(),
        hostname=socket.gethostname(),
    )

    fingerprint = CapabilityFingerprint(
        schema_version="1.0",
        metadata=metadata,
        capabilities=caps,
    )

    return fingerprint, exit_code
