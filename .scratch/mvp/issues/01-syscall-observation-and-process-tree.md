# 01: Linux Process & Syscall Observation Engine

**What to build:** A robust process execution and syscall observation engine that executes arbitrary commands under recursive Linux tracing (`strace` / `/proc`), streaming raw events for file open/creat/unlink, process exec, network connect, and environment variables across all child processes.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Wrap target commands under `strace` with recursive multi-process tracking (`-f`).
- [ ] Intercept and parse `open`, `openat`, `creat`, `unlink`, `unlinkat` for read/write file operations.
- [ ] Intercept and parse `execve`, `execveat` for all spawned binaries and sub-shells.
- [ ] Intercept and parse `connect` syscalls for IPv4 and IPv6 network destinations.
- [ ] Inspect environment variables present during the trace session.
- [ ] Fallback gracefully when `strace` is absent or when running in constrained environments.
