# 06: GitHub Action Packaging for Automated Agent Verification

**What to build:** The `action.yml` GitHub Action definition and CI workflow integration allowing repositories to install and run AgentScope authority verification automatically on Pull Requests and agent-driven workflows.

**Blocked by:** 04: CLI Workflow and CI Baseline Verification Engine

**Status:** resolved

- [x] Create `action.yml` metadata with inputs (`baseline_path`, `candidate_path`, `fail_on_escalation`).
- [x] Define action entrypoint running `agentscope verify` and rendering markdown summary tables to `$GITHUB_STEP_SUMMARY`.
- [x] Document action usage in `README.md` with copy-pasteable YAML examples.
- [x] Test the action locally and in `.github/workflows/ci.yml`.
