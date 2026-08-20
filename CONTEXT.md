# AgentScope Domain Context & Architecture (`CONTEXT.md`)

## 1. Executive Summary & Mission

**AgentScope** is an open-source, local-first developer tool that captures the *actual authority surface* of AI coding agents during execution. It transforms low-level kernel syscalls, process trees, network sockets, and file operations into a deterministic, reproducible **Capability Fingerprint** (`agentscope.json`).

AgentScope brings the transparency of `strace`, the ergonomics of `git diff`, and the auditability of an SBOM to autonomous agent workflows.

---

## 2. Why Now & The Core Problem

As autonomous coding agents (Claude Code, Cursor, Codex, OpenCode, Aider, custom sidecars) gain broader permissions to execute bash commands, edit files, and connect to remote endpoints, traditional static analysis fails to predict agent behavior. Recent research (e.g., Zenity Labs, August 2026) demonstrates that malicious or hallucinating agent skills evade static checks and manifest unsafe authority only dynamically at runtime.

Existing security suites focus on enterprise runtime firewalls, prompt injection blockers, and SaaS control planes. AgentScope addresses the missing developer primitive: **local, observable, verifiable authority diffing**.

---

## 3. Ubiquitous Language & Domain Glossary

To ensure unambiguous terminology across tickets, code, and ADRs, the following definitions are canonical:

| Term | Definition |
| :--- | :--- |
| **Authority Surface** | The full set of resources (files read/written, commands executed, network endpoints contacted, credentials/env vars accessed) touched by an agent during a run. |
| **Capability Fingerprint** | A canonical, sorted, deterministic JSON artifact summarizing the observed authority surface. |
| **Trace Session** | A monitored execution of an agent command spawned and tracked by AgentScope from initialization to process termination. |
| **Observer (Tracer)** | The observation backend capturing kernel syscalls and process activity (`ptrace`, `/proc`, `eBPF`, `strace` wrappers). |
| **Raw Event** | An atomic kernel event emitted during tracing (e.g., `openat`, `execve`, `connect`, `read`, `write`). |
| **Normalizer** | The subsystem transforming raw kernel events into high-level semantic capability declarations. |
| **Capability Category** | One of the 5 canonical dimensions of authority: `filesystem.read`, `filesystem.write`, `process.execute`, `network.connect`, `credential.access`. |
| **Capability Delta (Diff)** | The structural difference between two fingerprints (or between a run and a baseline), highlighting newly introduced capabilities and risk levels. |
| **Baseline** | A committed, version-controlled reference fingerprint (`.agent/authority-baseline.json`) used for regression testing and CI verification. |
| **Risk Delta** | An assessment (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) computed from newly introduced high-risk capabilities (e.g., touching `~/.ssh`, `~/.aws`, writing CI workflows, invoking `curl` to untrusted IPs). |

---

## 4. Bounded Contexts & Component Architecture

```text
               +----------------------------------------+
               |          CLI Entrypoint & CI           |
               | (agentscope run / diff / baseline / verify)
               +-------------------+--------------------+
                                   |
                     +-------------+-------------+
                     |                           |
                     v                           v
         +-----------------------+   +-----------------------+
         |    Observer Context   |   |   Diff & Verification |
         |   (ptrace / procfs /  |   |        Context        |
         |    strace / ebpf)     |   |   (Delta / Risk Calc) |
         +-----------+-----------+   +-----------^-----------+
                     |                           |
                     | Raw Events                | Fingerprints
                     v                           |
         +-----------------------+               |
         |  Normalization Engine |               |
         |  (Path resolution, IP |               |
         |   categorization,     |               |
         |   credential filter)  |               |
         +-----------+-----------+               |
                     |                           |
                     | Normalized Capabilities   |
                     v                           |
         +---------------------------------------+---+
         |          Fingerprint Data Model           |
         | (Schema, Canonical Serialization, JSON)  |
         +-------------------------------------------+
```

### 4.1. Observer Context (`agentscope.observer`)
- Spawns the agent process tree under tracking (`ptrace` with `PTRACE_O_TRACEFORK`/`CLONE`, or `strace` JSON/stream parsing, `/proc/<pid>/net`, `/proc/<pid>/fd`).
- Captures child subprocesses recursively.
- Emits raw syscall records:
  - `openat`, `creat`, `unlink`, `rename` -> File system operations.
  - `execve`, `execveat` -> Process executions.
  - `connect`, `sendto` -> Network socket operations.
  - `getenv` / `/proc/environ` / sensitive file opens -> Credential access.

### 4.2. Normalization Context (`agentscope.normalizer`)
- Resolves relative paths to absolute and relative-to-repo forms (`./src/**`, `~/.ssh/id_rsa`).
- Groups file accesses into directory globs when threshold densities are met.
- Resolves socket IPs to hostnames via reverse DNS or TLS SNI when available.
- Categorizes sensitive secrets and token accesses (e.g., `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `~/.config/gh/hosts.yml`).

### 4.3. Fingerprint Model (`agentscope.models`)
- Implements the strict, deterministic data model.
- Key properties:
  - `version`: Fingerprint format version (e.g. `"1.0"`).
  - `agent`: Agent identifier / command invoked.
  - `metadata`: Timestamp, duration, exit code, working directory.
  - `filesystem`:
    - `read`: List of file paths / globs read.
    - `write`: List of file paths / globs written or modified.
  - `commands`: List of distinct executable names invoked.
  - `network`: List of hostnames / IP addresses contacted.
  - `secrets`: List of environment variables or sensitive files touched.

### 4.4. Diff & Verification Context (`agentscope.diff`, `agentscope.verifier`)
- Compares Baseline $A$ and Candidate $B$.
- Generates structural additions ($+$) and removals ($-$).
- Computes Risk Severity:
  - `CRITICAL`: Access to private SSH keys, cloud credentials, shell injection to remote hosts.
  - `HIGH`: Modification of CI/CD configs (`.github/workflows/`), new unexpected network egress, credential env read.
  - `MEDIUM`: New execution binaries (e.g. `curl`, `wget`, `docker`).
  - `LOW`: Safe repo-local file additions.

---

## 5. System Invariants

1. **Deterministic Fingerprints**: Two runs producing the identical raw events must produce byte-for-byte identical capability fingerprints (sorted lists, standardized relative paths).
2. **Zero In-Process Interference**: AgentScope does not modify agent execution or inject runtime payloads into the agent VM/process unless explicitly running in sandboxed enforcement mode.
3. **Offline Operability**: All core diffing, fingerprinting, and observation capabilities work without external network dependencies.
4. **Non-Goal: Enterprise Control Planes**: AgentScope will not incorporate multi-tenant SSO, SaaS portals, or dynamic cloud policy servers. It remains a sharp, local CLI and CI tool.
