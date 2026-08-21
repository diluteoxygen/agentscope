"""
eBPF Kernel Probe Driver for AgentScope.
Provides zero-overhead tracepoint observation when running with kernel privileges.
"""

from __future__ import annotations
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Set, Tuple, List

from ..models import CapabilityFingerprint, Capabilities, FilesystemCapabilities
from ..normalizer import Normalizer


class EBPFDriver:
    """
    eBPF tracepoint driver for Linux kernel authority tracing.
    """

    def __init__(self, cwd: Optional[str] = None):
        self.cwd = Path(cwd).resolve() if cwd else Path.cwd().resolve()
        self.normalizer = Normalizer(str(self.cwd))
        self.probe_src = Path(__file__).parent / "probe.c"

    @classmethod
    def is_supported(cls) -> bool:
        """
        Checks if eBPF tracepoints can be attached (requires root / CAP_BPF / CAP_SYS_ADMIN and Linux).
        """
        if os.name != "posix":
            return False
        if os.geteuid() != 0:
            return False
        try:
            return Path("/sys/kernel/debug/tracing").exists()
        except (PermissionError, FileNotFoundError, OSError):
            return False

    def parse_event(self, event_type: int, comm: str, path: str) -> Tuple[Set[str], Set[str], Set[str]]:
        """
        Translates raw eBPF event into reads/writes/commands.
        """
        reads: Set[str] = set()
        writes: Set[str] = set()
        commands: Set[str] = set()

        if event_type == 1:  # OPEN
            reads.add(path)
        elif event_type == 2:  # EXEC
            commands.add(path)

        return reads, writes, commands
