# ADR 0003: CLI Design and CI Baseline Verification Engine

## Status
Accepted

## Context
Developers need a fast, frictionless developer experience that integrates into both local terminal workflows and GitHub Actions / GitLab CI pipelines.

The tool must support 4 primary workflows:
1. `agentscope run <command>`: Trace command execution, generate `agentscope.json`.
2. `agentscope diff <fp1.json> <fp2.json>`: Compare two capability fingerprints and display a colored terminal diff.
3. `agentscope baseline [path]`: Record the current run's fingerprint as `.agent/authority-baseline.json`.
4. `agentscope verify [candidate] [--baseline <path>]`: Verify a candidate run against the baseline and exit with code `0` on pass or `1` on capability escalation.

## Decision
1. **Command Line Interface**: Build the CLI with standard argument parsing, colored rich output for terminal diffs, and structured JSON output for CI automation (`--json`).
2. **Baseline Storage**: Standardize on `.agent/authority-baseline.json` as the default committed project authority baseline.
3. **CI Action**: Package AgentScope as a GitHub Action (`diluteoxygen/agentscope@v1` or local action) that runs `agentscope verify` against pull requests or automated agent runs.

## Consequences
- **Positive**: Direct compatibility with existing Git workflows and automated CI pipelines.
- **Positive**: Immediate developer utility without requiring account creation or network connectivity.
