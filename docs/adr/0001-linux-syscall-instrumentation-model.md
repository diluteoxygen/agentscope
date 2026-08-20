# ADR 0001: Linux Syscall Instrumentation Model

## Status
Accepted

## Context
AI coding agents execute shell commands, edit files across the filesystem, invoke network tools (like `curl`, `pip`, `npm`), and access environment variables. To accurately record an agent's *actual* authority surface rather than relying on LLM self-reporting or prompt static analysis, AgentScope needs low-overhead, reliable process and kernel instrumentation on Linux.

Options considered:
1. **`strace` Subprocess Wrapper**: Spawn the target command under `strace -f -e trace=file,process,network,desc -qq` and stream-parse syscall events.
2. **Native `ptrace` (C/Rust/Python)**: Attach directly via `PTRACE_SEIZE` / `PTRACE_SETOPTIONS` with `PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE`.
3. **eBPF (Tracepoints/kprobes)**: Attach kernel probes to `sys_enter_openat`, `sys_enter_execve`, `sys_enter_connect`.
4. **LD_PRELOAD shim**: Inject a dynamic shared library intercepting libc functions (`open`, `execve`, `connect`).

## Decision
For **v0.1**, AgentScope implements a **hybrid `strace` stream-observer + `/proc` inspection engine**, with an architecture abstracted behind an `Observer` interface to allow a native `ptrace` / `eBPF` driver backend in subsequent iterations.

Rationale:
- **`strace` Subprocess Engine**: Available out-of-the-box on virtually every Linux distribution and GitHub Actions runner without requiring root/`CAP_SYS_ADMIN` privileges (which eBPF requires). Handles recursive sub-process fork/exec tracking automatically.
- **`/proc` polling/inspection**: Complements syscall tracking for environment variable inspection and initial socket inode mapping.
- **Pluggable Observer Interface**: Allows seamless upgrade to eBPF for high-throughput enterprise environments without modifying the normalizer or fingerprint model.

## Consequences
- **Positive**: Works immediately on developer machines and in CI without root permissions or special kernel headers.
- **Positive**: Complete process tree capture down through nested sub-shells, `npm`, `git`, and build tools.
- **Negative**: Tracing introduces minor CPU execution overhead (~5–15%), acceptable for AI agent workloads where model latency dominates.
