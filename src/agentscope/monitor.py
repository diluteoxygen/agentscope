"""
Live Multi-Pane Terminal UI (TUI) Forensic Monitor for real-time AI agent observation.
Pure Python standard library (ANSI escape sequences & curses compatibility) with zero external dependencies.
"""

from __future__ import annotations
import os
import re
import sys
import time
import shutil
import subprocess
from typing import List, Set, Optional, Tuple, Dict
from pathlib import Path
from collections import deque

from .models import CapabilityFingerprint, Capabilities, FilesystemCapabilities, RiskLevel
from .observer import parse_strace_output, RE_PID_PREFIX
from .normalizer import Normalizer
from .auditor import EnvAuditor
from .wrappers import get_agent_profile


class TerminalMonitor:
    """
    Renders a responsive multi-pane terminal forensic dashboard during agent execution.
    """

    def __init__(self, agent_name: str = "agent"):
        self.agent_name = agent_name
        self.profile = get_agent_profile(agent_name)
        self.reads: Set[str] = set()
        self.writes: Set[str] = set()
        self.commands: Set[str] = set()
        self.network: Set[str] = set()
        self.secrets: Set[str] = set()
        self.active_pids: Set[int] = set()
        self.current_risk = RiskLevel.LOW
        self.events: List[Tuple[str, str, str]] = []  # (category, description, color)
        self.normalizer = Normalizer()
        self.recent_timestamps = deque()
        self.total_syscalls = 0

    def update_with_line(self, raw_line: str) -> None:
        """
        Parses a single strace event line and updates the monitor state and metrics.
        """
        now = time.time()
        self.total_syscalls += 1
        self.recent_timestamps.append(now)
        while self.recent_timestamps and self.recent_timestamps[0] < now - 1.0:
            self.recent_timestamps.popleft()

        # Extract PID
        m_pid = re.match(r"^\[pid\s+(\d+)\]", raw_line.strip())
        if m_pid:
            self.active_pids.add(int(m_pid.group(1)))

        r, w, c, n = parse_strace_output([raw_line])
        for path in r:
            if not self.normalizer.is_system_noise(path):
                norm = self.normalizer.normalize_path(path)
                if norm not in self.reads:
                    self.reads.add(norm)
                    self._add_event("READ", norm, "\033[94m")  # Blue
                    for s in self.normalizer.detect_secrets(path):
                        self.secrets.add(s)
                        self._add_event("SECRET", f"Path accessed: {s}", "\033[91m")  # Red

        for path in w:
            if not self.normalizer.is_system_noise(path):
                norm = self.normalizer.normalize_path(path)
                if norm not in self.writes:
                    self.writes.add(norm)
                    self._add_event("WRITE", norm, "\033[93m")  # Yellow
                    for s in self.normalizer.detect_secrets(path):
                        self.secrets.add(s)
                        self._add_event("SECRET", f"Path touched: {s}", "\033[91m")

        for cmd in c:
            cmd_name = Path(cmd).name
            if cmd_name and cmd_name not in self.commands:
                self.commands.add(cmd_name)
                self._add_event("EXEC", cmd_name, "\033[95m")  # Magenta

        for dest in n:
            dest_clean = dest.strip()
            if dest_clean and dest_clean not in self.network:
                self.network.add(dest_clean)
                self._add_event("NET", dest_clean, "\033[96m")  # Cyan

        # Dynamic Risk Gauge
        if self.secrets:
            self.current_risk = RiskLevel.CRITICAL
        elif any(".github" in path or ".gitlab" in path for path in self.writes):
            self.current_risk = RiskLevel.HIGH
        elif self.network:
            self.current_risk = RiskLevel.MEDIUM

    def _add_event(self, category: str, msg: str, color: str) -> None:
        self.events.append((category, msg, color))
        if len(self.events) > 12:
            self.events.pop(0)

    def render_frame(self, elapsed_sec: float, root_pid: Optional[int] = None) -> str:
        """
        Generates a responsive multi-pane ASCII frame.
        """
        cols, rows = shutil.get_terminal_size((80, 24))
        w = max(78, min(cols, 100))

        risk_color = "\033[92m" if self.current_risk == RiskLevel.LOW else (
            "\033[93m" if self.current_risk == RiskLevel.MEDIUM else "\033[91m"
        )
        reset = "\033[0m"
        bold = "\033[1m"
        cyan = "\033[96m"
        dim = "\033[2m"

        rate = len(self.recent_timestamps)
        pid_str = f"PID: {root_pid}" if root_pid else f"PIDs: {len(self.active_pids) or 1}"
        agent_label = f"{self.agent_name}"
        if self.agent_name in ("antigravity", "agy"):
            agent_label = f"✨ {self.agent_name}"

        # Top border
        title = " AGENTSCOPE REAL-TIME FORENSIC MONITOR "
        border_top = f"{bold}┌─{title}{'─' * (w - 4 - len(title))}┐{reset}"
        
        # Header line
        header_text = f"Agent: {cyan}{agent_label:<14}{reset} {dim}{pid_str:<12}{reset} Time: {elapsed_sec:>5.1f}s   Rate: {rate:>3} calls/s   Risk: {risk_color}{bold}[ {self.current_risk.value} ]{reset}"
        # Strip ansi length for padding calculation
        visible_len = len(f"Agent: {agent_label:<14} {pid_str:<12} Time: {elapsed_sec:>5.1f}s   Rate: {rate:>3} calls/s   Risk: [ {self.current_risk.value} ]")
        padding_right = " " * max(0, w - 4 - visible_len)
        header_line = f"│ {header_text}{padding_right} │"

        div_line = f"├{'─' * (w - 2)}┤"

        # Split pane (Columns)
        col_w = (w - 5) // 2
        col2_w = w - 5 - col_w

        # Left Column: Filesystem & Exec
        c1_title = f"{bold}FILESYSTEM & EXECUTION{reset}"
        c2_title = f"{bold}PERIMETER & SECRETS{reset}"
        
        c1_lines = [
            f"Reads:    {len(self.reads)} files",
            f"Writes:   {len(self.writes)} files",
            f"Commands: {', '.join(sorted(list(self.commands))[:2]) or 'none'}",
            f"Syscalls: {self.total_syscalls} total",
        ]

        net_sample = list(self.network)[:1]
        net_str = net_sample[0] if net_sample else "none"
        if len(self.network) > 1:
            net_str += f" (+{len(self.network) - 1})"

        secret_sample = list(self.secrets)[:1]
        sec_str = "clean" if not secret_sample else f"{risk_color}{len(self.secrets)} touched ⚠{reset}"

        c2_lines = [
            f"Endpoints: {net_str}",
            f"Secrets:   {sec_str}",
            f"Children:  {len(self.active_pids)} tracked",
            f"Profile:   {self.profile.name if self.profile else 'generic'}",
        ]

        pane_rows = []
        pane_rows.append(f"│ {c1_title:<{col_w + 8}} │ {c2_title:<{col2_w + 8}} │")
        for i in range(4):
            l1 = c1_lines[i] if i < len(c1_lines) else ""
            l2 = c2_lines[i] if i < len(c2_lines) else ""
            pane_rows.append(f"│ {l1:<{col_w}} │ {l2:<{col2_w}} │")

        # Bottom Pane: Live Event Stream
        event_title = f"{bold}LIVE FORENSIC EVENT STREAM{reset}"
        event_header = f"├─ {event_title} {'─' * (w - 6 - len('LIVE FORENSIC EVENT STREAM'))}┤"
        
        event_rows = []
        if not self.events:
            event_rows.append(f"│ {dim}(waiting for syscall events...){reset}{' ' * (w - 34)} │")
        else:
            for cat, msg, color in self.events[-5:]:
                tag = f"{color}[{cat:<6}]{reset}"
                avail_space = w - 14
                trunc_msg = msg[:avail_space]
                pad = " " * max(0, avail_space - len(trunc_msg))
                event_rows.append(f"│ • {tag} {trunc_msg}{pad} │")

        border_bottom = f"{bold}└{'─' * (w - 2)}┘{reset}"

        all_lines = [border_top, header_line, div_line] + pane_rows + [event_header] + event_rows + [border_bottom]
        return "\n".join(all_lines)


def run_live_monitor(command: List[str], agent_name: str = "agent") -> Tuple[CapabilityFingerprint, int]:
    """
    Executes a command under the live multi-pane forensic dashboard.
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

        root_pid = proc.pid

        while proc.poll() is None:
            if proc.stderr:
                line = proc.stderr.readline()
                if line:
                    monitor.update_with_line(line)

            elapsed = time.time() - start_time
            frame = monitor.render_frame(elapsed, root_pid=root_pid)
            
            # Clear screen and redraw frame
            sys.stdout.write("\033[H\033[J" + frame + "\n")
            sys.stdout.flush()
            time.sleep(0.04)

        if proc.stderr:
            for line in proc.stderr.readlines():
                monitor.update_with_line(line)

        exit_code = proc.returncode

    finally:
        # Show cursor
        sys.stdout.write("\033[?25h\n")
        sys.stdout.flush()

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
