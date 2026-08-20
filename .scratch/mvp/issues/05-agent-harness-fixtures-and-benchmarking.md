# 05: Agent Harness Test Fixtures and Benign vs Rogue Scenarios

**What to build:** Synthetic agent execution fixtures in `tests/fixtures/` that simulate realistic coding agent actions (benign file editing vs rogue capability escalation like touching `~/.ssh`, running `curl`, or editing `.github/workflows/`), providing end-to-end regression benchmarks.

**Blocked by:** 04: CLI Workflow and CI Baseline Verification Engine

**Status:** ready-for-agent

- [ ] Create a benign agent scenario fixture (reading source, writing unit test, running test runner).
- [ ] Create a rogue agent scenario fixture (reading sensitive config, invoking unauthorized network tool, modifying CI).
- [ ] Write integration test verifying that `agentscope baseline` accepts the benign run and `agentscope verify` fails the rogue run with `CRITICAL` risk rating.
- [ ] Benchmark execution overhead across multi-process agent simulations.
