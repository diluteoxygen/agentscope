# AgentScope: AI Coding Agent Authority Forensics

AgentScope is a local, open-source tool that records an AI coding agent's *actual authority surface*—files, commands, network destinations, secrets, and processes—and converts it into a reproducible "capability fingerprint" you can diff between runs and enforce in CI.

## Core Philosophy

- **Observe Actions, Don't Guess Reasoning**: We instrument what the agent process actually touches via Linux syscalls and process tracing (`ptrace`, `/proc`, wrappers, eBPF).
- **Zero Enterprise Bloat**: No SaaS, no policy engine, no complex control planes. Just `run -> observe -> fingerprint -> diff`.
- **Reproducible & Diffable**: Fingerprints are canonical, deterministic JSON structures that act as an SBOM + Git diff for agent authority.
- **CI-Native**: Provide simple commands (`agentscope baseline`, `agentscope verify`) to catch capability creep before deployment.

## Engineering Standards

- **Language & Runtime**: Python 3.10+ (CLI & core engine), designed to interface cleanly with Linux system facilities.
- **Modularity**: Deep module boundaries separating Kernel Observation (`observer`), Event Normalization (`normalizer`), Fingerprint Data Model (`models`), and Diff Engine (`diff`).
- **Determinism**: Fingerprints must be sorted, canonical, and idempotent across runs on identical workloads.
- **Testing**: Every normalization rule and diff calculation must be covered by comprehensive unit and integration tests.

## Agent skills

### Issue tracker

GitHub issues via `gh` CLI (with offline markdown support in `.scratch/`). See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical 5-role triage vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout (`CONTEXT.md` at repo root, system ADRs in `docs/adr/`). See `docs/agents/domain.md`.
