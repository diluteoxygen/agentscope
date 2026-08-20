# Spec: AgentScope MVP

## Problem Statement

When AI coding agents (such as Claude Code, Cursor, OpenCode, Codex, or custom developer sidecars) run autonomously on developer machines or in CI environments, developers cannot determine their actual authority surface—what files they read/modified, which system binaries they spawned, what network endpoints they contacted, and what environment secrets they accessed. Static prompt or configuration analysis cannot predict dynamic behavior, and enterprise agent security platforms introduce heavy SaaS infrastructure, policy engines, and control planes when developers simply need local, reproducible, diffable forensic instrumentation.

## Solution

AgentScope provides a local-first, open-source CLI and CI verification engine that observes an agent's execution via Linux kernel syscalls and process tree tracking. It transforms raw events into a canonical, deterministic Capability Fingerprint (`agentscope.json`), computes capability deltas between runs or against a committed baseline (`.agent/authority-baseline.json`), and fails CI runs whenever an agent attempts unauthorized capability escalation.

## User Stories

1. As a software engineer, I want to wrap any AI coding agent execution command with `agentscope run -- <command>`, so that I can observe the complete authority surface of that agent run without modifying its source code.
2. As a software engineer, I want AgentScope to track all child processes and sub-shells recursively, so that indirect tool invocations (e.g. `npm` invoking `curl` or `node`) are fully captured.
3. As a software engineer, I want AgentScope to output a deterministic, canonical JSON capability fingerprint, so that identical runs produce byte-for-byte identical fingerprints.
4. As a software engineer, I want AgentScope to normalize file paths relative to my repository workspace, so that repo-local operations are clearly distinguished from access to user home directories or system paths.
5. As a software engineer, I want AgentScope to automatically detect access to sensitive paths (such as `~/.ssh/`, `~/.aws/`, `.env`, and `.github/workflows/`), so that high-risk file operations are prominently flagged.
6. As a software engineer, I want AgentScope to detect accessed sensitive environment variables (such as `GITHUB_TOKEN`, `OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`), so that secret exposure is audited.
7. As a software engineer, I want AgentScope to capture outbound network socket destinations (IP addresses and hostnames) contacted by the agent or its child processes, so that unauthorized exfiltration or external API access is visible.
8. As a software engineer, I want to compare two capability fingerprints using `agentscope diff <run1.json> <run2.json>`, so that I can inspect the capability delta with clear terminal diff formatting.
9. As a software engineer, I want `agentscope diff` to provide a machine-readable JSON output via `--json`, so that downstream automated tooling can consume the delta.
10. As a software engineer, I want `agentscope diff` to compute a risk delta rating (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) based on the nature of newly added capabilities, so that I can immediately gauge the severity of changes.
11. As a project maintainer, I want to commit a baseline authority profile to `.agent/authority-baseline.json` using `agentscope baseline`, so that my repository has a version-controlled contract of acceptable agent permissions.
12. As a CI engineer, I want to run `agentscope verify` in GitHub Actions or GitLab CI, so that any pull request or autonomous agent run that introduces unexpected capabilities fails the build.
13. As a security researcher, I want to run reproducible benchmarks comparing the authority surfaces of multiple agents across identical tasks, so that I can publish empirical findings on agent privilege utilization.

## Implementation Decisions

1. **Kernel Tracing Backend (Observer Context)**:
   - Primary v0.1 tracer uses Linux `strace` stream tracking (`-f -q -e trace=open,openat,creat,unlink,unlinkat,execve,execveat,connect`) combined with `/proc/<pid>/` inspection.
   - Tracing is encapsulated behind an abstract `Observer` interface to facilitate future native `ptrace` and `eBPF` backends without changing downstream normalization.

2. **Event Normalization & Filtering (Normalizer Context)**:
   - Standard system noise paths (dynamic linkers `/etc/ld.so.cache`, standard C libraries `/lib/**`, `/usr/lib/**`, locale files, `/dev/null`) are filtered by default.
   - Working directory paths are normalized to relative paths (`./src/**`), user home paths are normalized to `~/...`, and sensitive paths are classified.
   - Process executions are normalized to binary basenames (e.g. `/usr/bin/curl` -> `curl`).

3. **Capability Fingerprint Schema (Models Context)**:
   - Canonical structure adhering to Schema v1.0:
     - `schema_version`: `"1.0"`
     - `metadata`: `agent`, `command`, `timestamp`, `duration_ms`, `exit_code`, `cwd`, `hostname`
     - `capabilities`:
       - `filesystem`: `read` (sorted string array), `write` (sorted string array)
       - `commands`: (sorted string array)
       - `network`: (sorted string array)
       - `secrets`: (sorted string array)

4. **Diff Engine & Risk Scoring (Diff Context)**:
   - Evaluates set additions and subtractions across all 5 capability categories.
   - Risk rules:
     - `CRITICAL`: Access to private SSH keys, cloud credentials, tokens, or raw credential env vars.
     - `HIGH`: Modification of CI/CD configs (`.github/workflows/`), new unexpected network egress.
     - `MEDIUM`: Spawning high-capability utilities (`curl`, `docker`, `ssh`, `kubectl`) or reading external user configurations.
     - `LOW`: Standard repo-internal file additions.

5. **CLI & CI Verification (CLI Context)**:
   - Four primary verbs: `run`, `diff`, `baseline`, `verify`.
   - `verify` exits with code `0` on clean matches or safe modifications, and exit code `1` on unapproved capability escalation.

## Testing Decisions

- **Black-Box End-to-End Tests**: Execute real commands under `TraceObserver` (e.g. running a script that creates a file, reads an env var, and connects to a mock socket) and verify the resulting fingerprint structure.
- **Normalizer Unit Tests**: Test path normalization across relative paths, absolute paths, home paths, and system library noise patterns.
- **Diff & Risk Calculation Tests**: Verify clean diffs, addition diffs, removal diffs, and appropriate risk level assignments across all severity levels.
- **Test Compatibility**: Tests must run seamlessly with standard library `python3 -m unittest` and `pytest`.

## Out of Scope

- Enterprise SaaS dashboard, centralized multi-tenant database, or cloud telemetry.
- Dynamic runtime kernel blocking/sandboxing (AgentScope is an observation and verification tool, not an in-line firewall).
- Native macOS / Windows kernel tracing for v0.1 (Linux-first focus).

## Further Notes

- The resulting baseline artifact (`.agent/authority-baseline.json`) is designed to be committed directly into Git alongside repository code.
