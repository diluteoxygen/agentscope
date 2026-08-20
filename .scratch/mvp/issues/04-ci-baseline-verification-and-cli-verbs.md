# 04: CLI Workflow and CI Baseline Verification Engine

**What to build:** The CLI command suite integrating the observer, fingerprint model, diff engine, and CI verification. Supports `agentscope run`, `agentscope diff`, `agentscope baseline`, and `agentscope verify` with appropriate UNIX exit codes (code 0 for clean matches, code 1 for unauthorized capability escalations).

**Blocked by:** 03: Canonical Capability Fingerprint and Diff Engine

**Status:** ready-for-agent

- [ ] Implement `agentscope run -- <command>` writing `agentscope.json`.
- [ ] Implement `agentscope diff <fp1> <fp2> [--json]`.
- [ ] Implement `agentscope baseline [--input <path>] [--output <path>]` writing `.agent/authority-baseline.json`.
- [ ] Implement `agentscope verify [--candidate <path>] [--baseline <path>]` with exit code gating.
- [ ] Integrate CLI argument parser with detailed `--help` documentation and error handling.
- [ ] End-to-end integration tests covering all four CLI verbs.
