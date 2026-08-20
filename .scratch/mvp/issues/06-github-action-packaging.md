# 06: GitHub Action Packaging for Automated Agent Verification

**What to build:** The `action.yml` GitHub Action definition and CI workflow integration allowing repositories to install and run AgentScope authority verification automatically on Pull Requests and agent-driven workflows.

**Blocked by:** 04: CLI Workflow and CI Baseline Verification Engine

**Status:** ready-for-agent

- [ ] Create `action.yml` metadata with inputs (`baseline_path`, `candidate_path`, `fail_on_escalation`).
- [ ] Define action entrypoint running `agentscope verify` and rendering markdown summary tables to `$GITHUB_STEP_SUMMARY`.
- [ ] Document action usage in `README.md` with copy-pasteable YAML examples.
- [ ] Test the action locally and in `.github/workflows/ci.yml`.
