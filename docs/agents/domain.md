# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root: defines the AgentScope domain model, bounded contexts, ubiquitous language, and system invariants.
- **`docs/adr/`**: read ADRs that touch the area you are about to work in.

If any of these files don't exist, proceed silently. The `/domain-modeling` skill creates and updates them lazily when architectural decisions or terms are resolved.

## File structure

Single-context repository layout:

```text
/
├── CONTEXT.md
├── AGENTS.md
├── docs/
│   ├── adr/
│   │   ├── 0001-linux-syscall-instrumentation-model.md
│   │   ├── 0002-capability-fingerprint-schema.md
│   │   └── 0003-cli-and-ci-baseline-engine.md
│   └── agents/
│       ├── domain.md
│       ├── issue-tracker.md
│       └── triage-labels.md
└── src/
    └── agentscope/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, or a test name), use the exact terms defined in `CONTEXT.md`.

- **Authority Surface**: The set of resources (files, commands, network endpoints, credentials) accessible or accessed during execution.
- **Capability Fingerprint**: The normalized, canonical, JSON-serializable representation of an agent run's observed authority surface.
- **Run / Trace Session**: A single observed execution of an agent command.
- **Observer / Tracing Engine**: The kernel-level or process-level observer (`ptrace`, `/proc`, socket wrappers, eBPF) tracking syscall events.
- **Normalizer**: The component that converts raw kernel syscalls into canonical capability categories.
- **Capability Delta / Diff**: The structural difference between two fingerprints or between a run and a baseline.
- **Baseline**: The committed baseline authority profile (`.agent/authority-baseline.json`) against which CI checks run.

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding.
