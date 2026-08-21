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
from .benchmark import run_benchmark_suite, BenchmarkSuiteResult
from .wrappers import AGENT_PROFILES, get_agent_profile
from .visualizer import render_fingerprint_html, render_diff_html
from .monitor import run_live_monitor
from .policy import export_docker_flags, export_seccomp_profile, export_bwrap_command


def cmd_run(args: argparse.Namespace) -> int:
    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not cmd:
        print("Error: No command specified to run.", file=sys.stderr)
        return 1

    agent_name = args.agent or "agent"
    profile = get_agent_profile(agent_name)
    if profile:
        print(f"[*] Loaded profile for {profile.name}: {profile.description}")

    observer = TraceObserver()
    print(f"[*] AgentScope: Observing execution of: {' '.join(cmd)}")
    fingerprint, exit_code = observer.trace_command(
        command=cmd,
        agent_name=agent_name
    )

    out_path = Path(args.output or "agentscope.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(fingerprint.to_json())

    print(f"[+] Capability Fingerprint saved to: {out_path}")
    print(f"    - Files Read:     {len(fingerprint.capabilities.filesystem.read)}")
    print(f"    - Files Written:  {len(fingerprint.capabilities.filesystem.write)}")
    print(f"    - Commands:       {len(fingerprint.capabilities.commands)}")
    print(f"    - Network Sockets: {len(fingerprint.capabilities.network)}")
    print(f"    - Secrets:        {len(fingerprint.capabilities.secrets)}")

    if getattr(args, "html", None):
        html_path = Path(args.html)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_fingerprint_html(fingerprint, title=f"AgentScope Run: {agent_name}"))
        print(f"[+] Saved visual HTML report to: {html_path}")

    if getattr(args, "summary", False):
        print("\n" + render_fingerprint_report(fingerprint))

    return exit_code


def cmd_monitor(args: argparse.Namespace) -> int:
    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not cmd:
        print("Error: No command specified to monitor.", file=sys.stderr)
        return 1

    agent_name = args.agent or "agent"
    fingerprint, exit_code = run_live_monitor(command=cmd, agent_name=agent_name)

    out_path = Path(args.output or "agentscope.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(fingerprint.to_json())

    print(f"[+] Capability Fingerprint saved to: {out_path}")
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

    if getattr(args, "html", None):
        html_path = Path(args.html)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_diff_html(delta, title=f"AgentScope Diff: {path_a.name} -> {path_b.name}"))
        print(f"[+] Saved visual diff report to: {html_path}")

    if args.json:
        print(json.dumps(delta.to_dict(), indent=2))
    elif not getattr(args, "html", None):
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


def render_fingerprint_report(fp: CapabilityFingerprint) -> str:
    lines = [
        "AUTHORITY FINGERPRINT REPORT",
        "─" * 40,
    ]
    if fp.metadata:
        lines.append(f"Agent:     {fp.metadata.agent}")
        lines.append(f"Command:   {' '.join(fp.metadata.command)}")
        lines.append(f"Duration:  {fp.metadata.duration_ms}ms")
        lines.append(f"Exit Code: {fp.metadata.exit_code}")
        lines.append("─" * 40)

    caps = fp.capabilities
    if caps.secrets:
        lines.append("SECRETS ACCESSED:")
        for s in caps.secrets:
            lines.append(f"  • {s} ⚠")
        lines.append("")

    if caps.filesystem.write:
        lines.append(f"FILES WRITTEN ({len(caps.filesystem.write)}):")
        for w in caps.filesystem.write:
            lines.append(f"  • {w}")
        lines.append("")

    if caps.filesystem.read:
        lines.append(f"FILES READ ({len(caps.filesystem.read)}):")
        for r in caps.filesystem.read:
            lines.append(f"  • {r}")
        lines.append("")

    if caps.commands:
        lines.append(f"COMMANDS EXECUTED ({len(caps.commands)}):")
        for c in caps.commands:
            lines.append(f"  • {c}")
        lines.append("")

    if caps.network:
        lines.append(f"NETWORK ENDPOINTS ({len(caps.network)}):")
        for n in caps.network:
            lines.append(f"  • {n}")
        lines.append("")

    lines.append("─" * 40)
    return "\n".join(lines)


def cmd_report(args: argparse.Namespace) -> int:
    in_path = Path(args.input or "agentscope.json")
    if not in_path.exists():
        print(f"Error: Fingerprint not found: {in_path}", file=sys.stderr)
        return 1

    fp = CapabilityFingerprint.from_json(in_path.read_text())

    if getattr(args, "html", None):
        html_path = Path(args.html)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_fingerprint_html(fp, title=f"AgentScope Report: {in_path.name}"))
        print(f"[+] Saved visual HTML report to: {html_path}")
        return 0

    print(render_fingerprint_report(fp))
    return 0


def cmd_export_policy(args: argparse.Namespace) -> int:
    in_path = Path(args.input or ".agent/authority-baseline.json")
    if not in_path.exists():
        in_path = Path("agentscope.json")

    if not in_path.exists():
        print(f"Error: Fingerprint not found at {args.input or in_path}", file=sys.stderr)
        return 1

    fp = CapabilityFingerprint.from_json(in_path.read_text())
    fmt = (args.format or "docker").lower()

    if fmt == "docker":
        flags = export_docker_flags(fp)
        output_str = " \\\n  ".join(["docker run -it"] + flags)
    elif fmt == "seccomp":
        profile = export_seccomp_profile(fp)
        output_str = json.dumps(profile, indent=2)
    elif fmt == "bwrap":
        bwrap_args = export_bwrap_command(fp)
        output_str = " ".join(bwrap_args)
    else:
        print(f"Error: Unknown format '{fmt}'. Choose from 'docker', 'seccomp', 'bwrap'.", file=sys.stderr)
        return 1

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output_str + "\n")
        print(f"[+] Exported {fmt} security policy to: {out}")
    else:
        print(output_str)

    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    config_path = Path(args.config) if getattr(args, "config", None) else None
    if config_path and config_path.exists():
        tasks = json.loads(config_path.read_text())
    else:
        fixtures_dir = Path(__file__).parent.parent.parent / "tests" / "fixtures"
        benign_script = str(fixtures_dir / "benign_agent.py")
        rogue_script = str(fixtures_dir / "rogue_agent.py")

        tasks = [
            {"name": "claude-code", "command": [sys.executable, benign_script]},
            {"name": "untrusted-agent", "command": [sys.executable, rogue_script]}
        ]

    suite_res = run_benchmark_suite(tasks)

    if getattr(args, "json", False):
        print(json.dumps(suite_res.to_dict(), indent=2))
    else:
        print(suite_res.to_markdown_table())

    if getattr(args, "output", None):
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(suite_res.to_markdown_table() if not getattr(args, "json", False) else json.dumps(suite_res.to_dict(), indent=2))
        print(f"[+] Saved benchmark results to: {out}")

    return 0


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
    p_run.add_argument("--summary", "-s", action="store_true", help="Print detailed report after run")
    p_run.add_argument("--html", help="Generate standalone visual HTML report")
    p_run.add_argument("command", nargs=argparse.REMAINDER, help="The command to trace")

    # monitor (Live TUI)
    p_mon = subparsers.add_parser("monitor", help="Run agent under live real-time terminal TUI dashboard")
    p_mon.add_argument("--output", "-o", help="Output path for fingerprint JSON (default: agentscope.json)")
    p_mon.add_argument("--agent", "-a", default="agent", help="Agent identifier (default: agent)")
    p_mon.add_argument("command", nargs=argparse.REMAINDER, help="The command to trace")

    # diff
    p_diff = subparsers.add_parser("diff", help="Diff two capability fingerprints")
    p_diff.add_argument("file_a", help="Baseline fingerprint JSON")
    p_diff.add_argument("file_b", help="Candidate fingerprint JSON")
    p_diff.add_argument("--json", action="store_true", help="Output machine-readable JSON diff")
    p_diff.add_argument("--html", help="Generate standalone visual HTML diff report")

    # baseline
    p_base = subparsers.add_parser("baseline", help="Commit a fingerprint as project baseline (.agent/authority-baseline.json)")
    p_base.add_argument("--input", "-i", default="agentscope.json", help="Input fingerprint JSON")
    p_base.add_argument("--output", "-o", default=".agent/authority-baseline.json", help="Destination baseline path")

    # verify
    p_ver = subparsers.add_parser("verify", help="Verify candidate run against baseline in CI")
    p_ver.add_argument("--candidate", "-c", default="agentscope.json", help="Candidate run fingerprint")
    p_ver.add_argument("--baseline", "-b", default=".agent/authority-baseline.json", help="Baseline fingerprint")
    p_ver.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # export-policy
    p_pol = subparsers.add_parser("export-policy", help="Export hardened sandbox policy (docker, seccomp, bwrap)")
    p_pol.add_argument("--format", "-f", choices=["docker", "seccomp", "bwrap"], default="docker", help="Policy export target")
    p_pol.add_argument("--input", "-i", help="Input baseline or fingerprint JSON")
    p_pol.add_argument("--output", "-o", help="Destination policy output file")

    # report / view
    for cmd_name in ["report", "view"]:
        p_rep = subparsers.add_parser(cmd_name, help="Display structured report from a fingerprint JSON")
        p_rep.add_argument("input", nargs="?", default="agentscope.json", help="Input fingerprint JSON")
        p_rep.add_argument("--html", help="Generate standalone visual HTML report")

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Run multi-agent authority comparison benchmark")
    p_bench.add_argument("--config", "-c", help="Path to JSON benchmark task suite definition")
    p_bench.add_argument("--output", "-o", help="Path to save benchmark markdown report")
    p_bench.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(1)

    commands = {
        "run": cmd_run,
        "monitor": cmd_monitor,
        "diff": cmd_diff,
        "baseline": cmd_baseline,
        "verify": cmd_verify,
        "report": cmd_report,
        "view": cmd_report,
        "export-policy": cmd_export_policy,
        "benchmark": cmd_benchmark,
    }

    handler = commands.get(args.subcommand)
    if handler:
        sys.exit(handler(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
