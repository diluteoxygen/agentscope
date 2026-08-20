# ADR 0002: Capability Fingerprint Schema and Normalization

## Status
Accepted

## Context
Raw kernel syscalls produce thousands of low-level events (e.g., dynamic linker opens of `/lib/x86_64-linux-gnu/libc.so.6`, runtime locale reads, repeated stat calls). These low-level details create noise and make fingerprints non-reproducible.

AgentScope requires a normalized, deterministic format that:
1. Filters OS-level boilerplate (system libraries, compiler internals).
2. Highlights security-critical resources (user repos, user home configurations, credentials, external networks, executable binaries).
3. Produces canonical JSON that diffs cleanly in Git, terminal output, and CI logs.

## Decision
We define the **AgentScope Fingerprint Schema v1.0**:

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
        "~/.config/git/config",
        "src/**"
      ],
      "write": [
        ".github/workflows/ci.yml",
        "src/utils.py"
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

Rules:
- All path lists and command sets are deduplicated and lexicographically sorted.
- Paths within the working directory are normalized to relative paths (`./src/**`).
- Sensitive paths outside the repo (e.g., `~/.ssh/`, `~/.aws/`, `~/.config/`) are explicitly preserved and surfaced.
- System library reads (`/lib/**`, `/usr/lib/**`, `/etc/ld.so.*`) are filtered into an optional baseline category or omitted by default.

## Consequences
- **Positive**: Clean, concise fingerprints with zero nondeterministic jitter.
- **Positive**: Diffs directly correspond to developer-understandable capabilities.
