# 02: Event Normalization and Sensitive Resource Classification

**What to build:** The normalization subsystem that converts raw syscall events into clean, categorized, and deduplicated capabilities. It resolves relative paths against the project root, filters OS-level dynamic library noise, and classifies sensitive paths (`~/.ssh/`, `~/.aws/`, `.env`, `.github/workflows/`) and credentials.

**Blocked by:** 01: Linux Process & Syscall Observation Engine

**Status:** ready-for-agent

- [ ] Normalize paths into `./<relative-path>` for workspace items, `~/<path>` for home items, and absolute paths for others.
- [ ] Filter out OS-level boilerplate noise (`/lib/`, `/usr/lib/`, `/etc/ld.so.*`, `/proc/self/maps`).
- [ ] Implement regex-based sensitive file classification for SSH keys, AWS credentials, git tokens, and CI workflows.
- [ ] Extract and categorize sensitive environment variables (`GITHUB_TOKEN`, `OPENAI_API_KEY`, etc.).
- [ ] Normalize command names to executable basenames (`/usr/bin/curl` -> `curl`).
- [ ] Unit tests for all normalization rules and edge cases.
