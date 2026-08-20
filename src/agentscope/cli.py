"""
Command line interface for AgentScope.
"""

from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .models import CapabilityFingerprint, RiskLevel
from .observer import TraceObserver
from .diff import diff_fingerprints, format_terminal_diff


def cmd_run(args: argparse.Namespace) -> int:
    if not args.command:
        print("Error: No command specified to run.", file=sys.stderr)
        return 1

    observer = TraceObserver()
    print(f"[*] AgentScope: Observing execution of: {' '.join(args.command)}")
    fingerprint, exit_code = observer.trace_command(
        command=args.command,
        agent_name=args.agent or "agent"
    )

    out_path = Path(args.output or "agentscope.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(fingerprint.to_json())

    print(f"[+] Capability Fingerprint saved to: {out_path}")
    print(f"    - Files Read:    {len(fingerprint.capabilities.filesystem.read)}")
    print(f"    - Files Written: {len(fingerprint.capabilities.filesystem.write)}")
    print(f"    - Commands:      {len(fingerprint.capabilities.commands)}")
    print(f"    - Network Sockets:{len(fingerprint.capabilities.network)}")
    print(f"    - Secrets:       {len(fingerprint.capabilities.secrets)}")

    return exit_code


def cmd_diff(args: argparse.Namespace) -> int:
    path_a = Path(args.file_a)
    path_b = Path(args.file_b)

    if not path_a.exists():
        print(f"Error: Baseline file not found: {path_a}", file=sys.stderr)
        return 1
    if not path_b.exists():
        print(f"Error: Candidate file not found: {path_b}", file=sys.stderr)
        return 1

    fp_a = CapabilityFingerprint.from_json(path_a.read_text())
    fp_b = CapabilityFingerprint.from_json(path_b.read_text())

    delta = diff_fingerprints(fp_a, fp_b)

    if args.json:
        print(json.dumps(delta.to_dict(), indent=2))
    else:
        print(format_terminal_diff(delta, title=f"DIFF: {path_a.name} -> {path_b.name}"))

    return 1 if delta.has_escalations and delta.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) else 0


def cmd_baseline(args: argparse.Namespace) -> int:
    in_path = Path(args.input or "agentscope.json")
    out_path = Path(args.output or ".agent/authority-baseline.json")

    if not in_path.exists():
        print(f"Error: Source fingerprint not found: {in_path}", file=sys.stderr)
        print("Run `agentscope run -- <command>` first to generate one.", file=sys.stderr)
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    content = in_path.read_text()
    # Validate JSON
    fp = CapabilityFingerprint.from_json(content)
    out_path.write_text(fp.to_json())

    print(f"[+] Established authority baseline at: {out_path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    baseline_path = Path(args.baseline or ".agent/authority-baseline.json")
    candidate_path = Path(args.candidate or "agentscope.json")

    if not baseline_path.exists():
        print(f"Error: Baseline not found at {baseline_path}. Run `agentscope baseline` first.", file=sys.stderr)
        return 1

    if not candidate_path.exists():
        print(f"Error: Candidate run fingerprint not found at {candidate_path}.", file=sys.stderr)
        return 1

    base_fp = CapabilityFingerprint.from_json(baseline_path.read_text())
    cand_fp = CapabilityFingerprint.from_json(candidate_path.read_text())

    delta = diff_fingerprints(base_fp, cand_fp)

    if args.json:
        print(json.dumps(delta.to_dict(), indent=2))
    else:
        print("\n================ AGENTSCOPE CI VERIFICATION ================")
        if not delta.has_escalations:
            print("✓ PASS: Authority matches baseline profile cleanly.")
            print("============================================================\n")
            return 0
        else:
            print("⚠ BUILD FAILED: Unseen capabilities detected!\n")
            print(format_terminal_diff(delta, title="UNSEEN CAPABILITIES"))
            print("\n============================================================\n")
            return 1

    return 1 if delta.has_escalations else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentscope",
        description="Local capability fingerprinting and authority forensics for AI coding agents."
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available commands")

    # run
    p_run = subparsers.add_parser("run", help="Trace an agent command and generate agentscope.json")
    p_run.add_argument("--output", "-o", help="Output path for fingerprint JSON (default: agentscope.json)")
    p_run.add_argument("--agent", "-a", default="agent", help="Agent identifier (default: agent)")
    p_run.add_argument("command", nargs=argparse.REMAINDER, help="The command to trace")

    # diff
    p_diff = subparsers.add_parser("diff", help="Diff two capability fingerprints")
    p_diff.add_argument("file_a", help="Baseline fingerprint JSON")
    p_diff.add_argument("file_b", help="Candidate fingerprint JSON")
    p_diff.add_argument("--json", action="store_true", help="Output machine-readable JSON diff")

    # baseline
    p_base = subparsers.add_parser("baseline", help="Commit a fingerprint as project baseline (.agent/authority-baseline.json)")
    p_base.add_argument("--input", "-i", default="agentscope.json", help="Input fingerprint JSON")
    p_base.add_argument("--output", "-o", default=".agent/authority-baseline.json", help="Destination baseline path")

    # verify
    p_ver = subparsers.add_parser("verify", help="Verify candidate run against baseline in CI")
    p_ver.add_argument("--candidate", "-c", default="agentscope.json", help="Candidate run fingerprint")
    p_ver.add_argument("--baseline", "-b", default=".agent/authority-baseline.json", help="Baseline fingerprint")
    p_ver.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(1)

    commands = {
        "run": cmd_run,
        "diff": cmd_diff,
        "baseline": cmd_baseline,
        "verify": cmd_verify,
    }

    handler = commands.get(args.subcommand)
    if handler:
        sys.exit(handler(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
