# 03: Canonical Capability Fingerprint and Diff Engine

**What to build:** The deterministic capability fingerprint data model and the diffing engine. It guarantees byte-for-byte reproducible JSON output (`schema_version: 1.0`), calculates structural capability deltas (additions/removals across files, commands, network, secrets), assigns risk scores (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and renders clear terminal / JSON output.

**Blocked by:** 02: Event Normalization and Sensitive Resource Classification

**Status:** ready-for-agent

- [ ] Implement canonical sorting and deduplication across all capability arrays in `CapabilityFingerprint`.
- [ ] Implement `diff_fingerprints(baseline, candidate)` returning a `CapabilityDelta`.
- [ ] Calculate `RiskLevel` and human-readable `risk_reasons` based on newly introduced capabilities.
- [ ] Format human-readable colored ASCII terminal diffs for developers.
- [ ] Format machine-readable JSON output for automated tooling.
- [ ] Comprehensive unit tests for diff calculations and risk ratings.
