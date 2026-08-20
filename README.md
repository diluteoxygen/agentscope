# agentscope

agentscope traces what an AI coding agent touches during a run (files read and written, commands executed, outbound network destinations, and accessed environment variables). It writes a deterministic JSON fingerprint and lets you diff authority changes between runs or enforce an authority baseline in CI.

## The problem

Static analysis cannot predict what an autonomous agent will do once it starts executing shell commands and scripts. Most runtime agent security tools are enterprise SaaS platforms with policy engines and cloud control planes.

agentscope is a local command-line tool. It runs on Linux, captures child process trees and syscalls with `strace` and `/proc`, and generates a plain JSON artifact. You can diff two runs with `agentscope diff` or fail pull requests with `agentscope verify` if an agent acquires new capabilities.

## How it looks

```text
RUN #184

Agent: claude
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

## Installation

Requirements: Linux with Python 3.10+ and `strace`.

```bash
pip install agentscope
```

For local development:

```bash
git clone https://github.com/diluteoxygen/agentscope.git
cd agentscope
pip install -e .
```

## Usage

### 1. Trace an agent run

Wrap your agent command:

```bash
agentscope run -- claude code
```

agentscope executes the command, traces all spawned child processes, and writes `agentscope.json` to the current working directory.

### 2. Diff two runs

Compare fingerprints from two separate runs:

```bash
agentscope diff run-183.json run-184.json
```

To get machine-readable output for scripts:

```bash
agentscope diff run-183.json run-184.json --json
```

### 3. Establish a baseline

Save the current fingerprint as your repository's committed baseline:

```bash
agentscope baseline
```

This writes `.agent/authority-baseline.json`. Check this file into git.

### 4. Verify in CI

Verify a new run against the committed baseline:

```bash
agentscope verify
```

If the agent stayed within its baseline, `agentscope verify` exits with code `0`. If new capabilities or sensitive accesses appear, it prints the delta and exits with code `1`.

```text
================ AGENTSCOPE CI VERIFICATION ================
⚠ BUILD FAILED: Unseen capabilities detected!

UNSEEN CAPABILITIES
────────────────────────────────────────
SECRETS
  + env:AWS_SECRET_ACCESS_KEY ⚠
FILES WRITTEN
  + .github/workflows/deploy.yml ⚠
COMMANDS
  + curl
NETWORK
  + api.stripe.com:443 ⚠
────────────────────────────────────────
RISK DELTA: CRITICAL
  • Accessed new secret(s): env:AWS_SECRET_ACCESS_KEY
  • Modified CI/CD workflow: .github/workflows/deploy.yml
  • New outbound network destination(s): api.stripe.com:443
============================================================
```

## GitHub Action

Add authority verification to `.github/workflows/ci.yml`:

```yaml
name: Verify agent authority
on: [pull_request, workflow_dispatch]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          sudo apt-get update && sudo apt-get install -y strace
          pip install agentscope
      - name: Run verification
        run: agentscope verify
```

## Fingerprint schema

Fingerprints are written as canonical JSON with sorted arrays:

```json
{
  "schema_version": "1.0",
  "metadata": {
    "agent": "claude",
    "command": ["claude", "code"],
    "timestamp": "2026-08-20T21:55:00Z",
    "duration_ms": 14200,
    "exit_code": 0,
    "cwd": "/workspace/payment-service"
  },
  "capabilities": {
    "filesystem": {
      "read": [
        "./src/**",
        "~/.config/git/config"
      ],
      "write": [
        "./src/utils.py",
        ".github/workflows/ci.yml"
      ]
    },
    "commands": [
      "curl",
      "git",
      "npm",
      "pytest"
    ],
    "network": [
      "api.github.com",
      "registry.npmjs.org"
    ],
    "secrets": [
      "GITHUB_TOKEN"
    ]
  }
}
```

## Architecture and design records

For detailed domain documentation and design rationales, see:
- [Domain context and ubiquitous language](CONTEXT.md)
- [Agent standards](AGENTS.md)
- [ADR 0001: Linux syscall instrumentation model](docs/adr/0001-linux-syscall-instrumentation-model.md)
- [ADR 0002: Capability fingerprint schema](docs/adr/0002-capability-fingerprint-schema.md)
- [ADR 0003: CLI and CI baseline engine](docs/adr/0003-cli-and-ci-baseline-engine.md)

## License

MIT
