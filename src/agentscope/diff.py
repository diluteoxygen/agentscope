"""
Diff engine for calculating capability deltas and assessing risk escalation.
"""

from __future__ import annotations
from typing import List, Tuple
from .models import CapabilityFingerprint, CapabilityDelta, RiskLevel


def diff_fingerprints(
    baseline: CapabilityFingerprint,
    candidate: CapabilityFingerprint
) -> CapabilityDelta:
    """
    Computes candidate capabilities relative to baseline capabilities.
    """
    base_caps = baseline.capabilities
    cand_caps = candidate.capabilities

    base_read = set(base_caps.filesystem.read)
    cand_read = set(cand_caps.filesystem.read)

    base_write = set(base_caps.filesystem.write)
    cand_write = set(cand_caps.filesystem.write)

    base_cmds = set(base_caps.commands)
    cand_cmds = set(cand_caps.commands)

    base_net = set(base_caps.network)
    cand_net = set(cand_caps.network)

    base_sec = set(base_caps.secrets)
    cand_sec = set(cand_caps.secrets)

    added_read = sorted(list(cand_read - base_read))
    removed_read = sorted(list(base_read - cand_read))

    added_write = sorted(list(cand_write - base_write))
    removed_write = sorted(list(base_write - cand_write))

    added_cmds = sorted(list(cand_cmds - base_cmds))
    removed_cmds = sorted(list(base_cmds - cand_cmds))

    added_net = sorted(list(cand_net - base_net))
    removed_net = sorted(list(base_net - cand_net))

    added_sec = sorted(list(cand_sec - base_sec))
    removed_sec = sorted(list(base_sec - cand_sec))

    risk_reasons: List[str] = []
    risk_level = RiskLevel.LOW

    # Assess Risk Escalation
    if added_sec:
        risk_level = RiskLevel.CRITICAL
        risk_reasons.append(f"Accessed new secret(s): {', '.join(added_sec)}")

    for w in added_write:
        if ".github/workflows" in w or ".gitlab-ci" in w:
            if risk_level != RiskLevel.CRITICAL:
                risk_level = RiskLevel.HIGH
            risk_reasons.append(f"Modified CI/CD workflow: {w}")

    if added_net:
        if risk_level not in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            risk_level = RiskLevel.HIGH
        risk_reasons.append(f"New outbound network destination(s): {', '.join(added_net)}")

    high_risk_cmds = {"curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "docker", "kubectl"}
    for cmd in added_cmds:
        if cmd in high_risk_cmds:
            if risk_level == RiskLevel.LOW:
                risk_level = RiskLevel.MEDIUM
            risk_reasons.append(f"Executed high-capability binary: {cmd}")

    for r in added_read:
        if r.startswith("~") and not r.startswith("~/Documents"):
            if risk_level == RiskLevel.LOW:
                risk_level = RiskLevel.MEDIUM
            risk_reasons.append(f"Read user home configuration: {r}")

    return CapabilityDelta(
        added_files_read=added_read,
        removed_files_read=removed_read,
        added_files_written=added_write,
        removed_files_written=removed_write,
        added_commands=added_cmds,
        removed_commands=removed_cmds,
        added_network=added_net,
        removed_network=removed_net,
        added_secrets=added_sec,
        removed_secrets=removed_sec,
        risk_level=risk_level,
        risk_reasons=risk_reasons,
    )


def format_terminal_diff(delta: CapabilityDelta, title: str = "CAPABILITY DELTA") -> str:
    """
    Renders a human-readable, colored ASCII delta summary.
    """
    lines = [
        f"\n{title}",
        "─" * 40,
    ]

    if not delta.has_escalations:
        lines.append("✓ No new capabilities detected (clean authority match).")
        lines.append(f"RISK DELTA: {delta.risk_level.value}")
        return "\n".join(lines)

    if delta.added_secrets:
        lines.append("SECRETS")
        for s in delta.added_secrets:
            lines.append(f"  + {s} ⚠")

    if delta.added_files_written:
        lines.append("FILES WRITTEN")
        for f in delta.added_files_written:
            warn = " ⚠" if (".github" in f or "~" in f) else ""
            lines.append(f"  + {f}{warn}")

    if delta.added_files_read:
        lines.append("FILES READ")
        for f in delta.added_files_read:
            warn = " ⚠" if "~" in f else ""
            lines.append(f"  + {f}{warn}")

    if delta.added_commands:
        lines.append("COMMANDS")
        for c in delta.added_commands:
            lines.append(f"  + {c}")

    if delta.added_network:
        lines.append("NETWORK")
        for n in delta.added_network:
            lines.append(f"  + {n} ⚠")

    lines.append("─" * 40)
    lines.append(f"RISK DELTA: {delta.risk_level.value}")
    if delta.risk_reasons:
        for r in delta.risk_reasons:
            lines.append(f"  • {r}")

    return "\n".join(lines)
