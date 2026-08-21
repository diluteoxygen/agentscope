"""
In-process environment variable access auditor using a lightweight LD_PRELOAD C shim.
"""

from __future__ import annotations
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Set, Optional, Tuple, List


SHIM_DIR = Path(__file__).parent / "shim"
SHIM_C_SRC = SHIM_DIR / "auditor.c"
SHIM_SO_PATH = SHIM_DIR / "libagentscope_audit.so"


def get_or_build_shim() -> Optional[Path]:
    """
    Returns the path to the compiled libagentscope_audit.so library, building it on-demand if missing.
    """
    if SHIM_SO_PATH.exists():
        return SHIM_SO_PATH

    if not SHIM_C_SRC.exists():
        return None

    compiler = shutil.which("gcc") or shutil.which("clang")
    if not compiler:
        return None

    try:
        SHIM_DIR.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(
            [
                compiler,
                "-shared",
                "-fPIC",
                "-O2",
                "-Wall",
                "-Wextra",
                str(SHIM_C_SRC),
                "-o",
                str(SHIM_SO_PATH),
                "-ldl",
            ],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0 and SHIM_SO_PATH.exists():
            return SHIM_SO_PATH
    except Exception:
        return None

    return None


class EnvAuditor:
    """
    Context manager that configures LD_PRELOAD to trace in-process getenv() accesses.
    """

    def __init__(self, log_dir: Optional[str] = None):
        self.shim_so = get_or_build_shim()
        self.enabled = self.shim_so is not None and self.shim_so.exists()
        session_id = uuid.uuid4().hex[:12]
        self.log_file = Path(log_dir or tempfile.gettempdir()) / f".agentscope_env_{session_id}.log"

    def get_injected_env(self, base_env: Optional[dict] = None) -> dict:
        """
        Returns an environment dictionary augmented with LD_PRELOAD and AGENTSCOPE_AUDIT_LOG.
        """
        env = dict(base_env if base_env is not None else os.environ)
        if self.enabled and self.shim_so:
            existing_preload = env.get("LD_PRELOAD", "")
            preload_val = str(self.shim_so)
            if existing_preload:
                preload_val = f"{preload_val}:{existing_preload}"

            env["LD_PRELOAD"] = preload_val
            env["AGENTSCOPE_AUDIT_LOG"] = str(self.log_file)
        return env

    def collect_accessed_keys(self) -> Set[str]:
        """
        Reads the audit log file and returns the set of environment variable keys accessed.
        """
        accessed_keys: Set[str] = set()
        if not self.log_file.exists():
            return accessed_keys

        try:
            content = self.log_file.read_text(errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if ":" in line:
                    _, key = line.split(":", 1)
                    key = key.strip()
                    if key:
                        accessed_keys.add(key)
        except Exception:
            pass

        return accessed_keys

    def cleanup(self) -> None:
        """
        Deletes the temporary audit log file.
        """
        try:
            if self.log_file.exists():
                self.log_file.unlink()
        except Exception:
            pass
