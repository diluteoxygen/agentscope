# AgentScope 🔍

> **What did your coding agent *actually* touch?**
>
> A local, open-source tool that records an AI coding agent’s actual authority surface—files, commands, network destinations, secrets, processes—and converts it into a reproducible **Capability Fingerprint** you can diff between runs and enforce in CI.

---

## The Gap

Most AI security tools answer:
> *"Was this action dangerous?"*

AgentScope answers something more primitive and verifiable:
> **"What could this agent actually touch during this run, and how did that authority change?"**

Think: **`strace` + Git diff + SBOM, but for AI agents.**

```text
RUN #184

Agent: Claude Code
Repo: payment-service
Duration: 11m 42s

AUTHORITY FINGERPRINT
────────────────────────────

FILES
  READ
    ./src/**                 247
    ~/.config/git/config       1 ⚠
    ~/.ssh/known_hosts         1

  WRITE
    ./src/**                  19
    .github/workflows/ci.yml   1 ⚠

COMMANDS
  git
  npm
  pytest
  curl                     ⚠ NEW

NETWORK
  registry.npmjs.org
  api.github.com
  104.x.x.x                ⚠ NEW

SECRETS
  GITHUB_TOKEN              touched ⚠

CAPABILITY DELTA
────────────────────────────

Previous run:
  filesystem: repo-only
  network: github + npm
  secrets: none

Current run:
  + ~/.config/git/config
  + .github/workflows/ci.yml
  + curl
  + GITHUB_TOKEN

RISK DELTA: HIGH
```

---

## Features

- 🔬 **Kernel & Syscall Observation**: Direct tracing of process trees, file accesses, binary executions, network sockets, and environment variables.
- 📜 **Canonical Capability Fingerprint**: Deterministic JSON output (`agentscope.json`) summarizing the exact authority surface.
- ⚡ **Zero-SaaS, Local-First**: No enterprise control planes, no cloud dashboards, no telemetry. Runs entirely on your machine.
- 🔄 **Authority Diffing**: Instant semantic comparison between two runs or between a run and your baseline.
- 🛡️ **CI Enforcement**: Fail pull requests or agent runs if unseen capabilities (e.g. accessing `~/.aws/credentials` or connecting to unknown IPs) are introduced.

---

## Quick Start

### Installation

```bash
pip install agentscope
# Or from local source
pip install -e .
```

### 1. Observe an Agent Run

Wrap any agent execution command:

```bash
agentscope run -- claude code
```

This generates `agentscope.json` in the current working directory.

### 2. Diff Two Agent Runs

```bash
agentscope diff run-183.json run-184.json
```

### 3. Establish a Baseline for CI

```bash
agentscope baseline
# Writes .agent/authority-baseline.json
```

### 4. Verify in CI

```bash
agentscope verify
```

If an agent attempts unauthorized capability escalation:

```text
AGENTSCOPE CI

✓ repository filesystem
✓ git
✓ npm
✓ pytest

NEW CAPABILITIES
+ network: api.stripe.com
+ file: ~/.aws/credentials
+ command: docker
+ write: .github/workflows/deploy.yml

BUILD FAILED: 4 previously unseen capabilities detected.
```

---

## GitHub Action

```yaml
name: Agent Authority Verification
on: [pull_request, workflow_dispatch]

jobs:
  verify-agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install AgentScope
        run: pip install agentscope
      - name: Verify Authority
        run: agentscope verify
```

---

## Architecture & Engineering Standards

See:
- [Domain Architecture & Context (`CONTEXT.md`)](CONTEXT.md)
- [Agent Guidelines & Standards (`AGENTS.md`)](AGENTS.md)
- [ADR 0001: Linux Syscall Instrumentation Model](docs/adr/0001-linux-syscall-instrumentation-model.md)
- [ADR 0002: Capability Fingerprint Schema](docs/adr/0002-capability-fingerprint-schema.md)
- [ADR 0003: CLI and CI Baseline Engine](docs/adr/0003-cli-and-ci-baseline-engine.md)

---

## License

MIT
