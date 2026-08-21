# How to Run & Verify AgentScope

This guide walks you through checking, executing, and testing the current version of **AgentScope** locally.

---

## 1. Quick Environment Check

Make sure you are running on Linux with Python 3.10+ and `strace`:

```bash
# Check Python version
python3 --version

# Check strace availability
strace -V | head -n 1

# Check GCC (for LD_PRELOAD secret interceptor)
gcc --version | head -n 1
```

---

## 2. Local Installation & Development Mode

Clone the repository and install with development dependencies:

```bash
git clone https://github.com/diluteoxygen/agentscope.git
cd agentscope
pip install -e .[dev]
```

To run AgentScope directly without installing globally:
```bash
PYTHONPATH=src python3 -m agentscope.cli --help
```

---

## 3. Core Commands & Practical Walkthrough

### 🚀 A. Trace Google Antigravity (`agy`)

Trace an autonomous agent session executed by Google Antigravity:

```bash
# Trace run with summary output
agentscope run --agent antigravity --summary -- agy "fix the auth middleware"

# Trace run and immediately generate visual HTML report
agentscope run --agent antigravity --html agy_report.html -- agy "generate tests"
```

AgentScope automatically records:
- Files read and written in your repository and `~/.gemini/antigravity-cli/`
- All spawned subcommands (`git`, `pytest`, `npm`)
- TLS connections to `generativelanguage.googleapis.com:443`
- Environment secrets accessed in-process (`GEMINI_API_KEY`, `GOOGLE_API_KEY`)

---

### 🖥️ B. Live Multi-Pane TUI Monitor

Watch an agent execute in real-time with live syscall rate meters, active child process counts, and dynamic risk scoring:

```bash
# Live monitoring with Google Antigravity
agentscope monitor --agent antigravity -- python3 -c "import os; print('Hello AGY')"

# Live monitoring with Claude Code
agentscope monitor --agent claude -- claude code
```

---

### 🛡️ C. Active Runtime Enforcement (Containment Firewall)

Enforce that an agent stays strictly within your repository's committed baseline. If a rogue command attempts to read `~/.ssh/id_rsa`, modify `.github/workflows/`, or connect to an unauthorized socket, AgentScope terminates the child process tree immediately with `SIGKILL`:

```bash
agentscope enforce --baseline .agent/authority-baseline.json -- agy "run migration"
```

---

### 🔍 D. Diffing Runs & Visual HTML Reports

Compare two capability fingerprints or render interactive offline HTML reports:

```bash
# Terminal Diff
agentscope diff baseline.json candidate.json

# Visual Interactive HTML Diff
agentscope diff baseline.json candidate.json --html diff_report.html

# View Single Fingerprint in Browser
agentscope view agentscope.json --html dashboard.html
```

---

### 🔒 E. Git Safety Hooks (Pre-Commit & Pre-Push)

Install automatic repository guards that block commits or pushes when unauthorized agent escalations occur:

```bash
# Install hooks into .git/hooks/
agentscope hook install

# Verify hook status
agentscope hook status

# Uninstall hooks
agentscope hook uninstall
```

---

### 📦 F. Export Hardened Sandbox Policies

Generate kernel confinement policies directly from your agent's baseline:

```bash
# Generate Docker run arguments
agentscope export-policy --format docker

# Generate Seccomp JSON filter
agentscope export-policy --format seccomp --output seccomp.json

# Generate Bubblewrap (bwrap) flags
agentscope export-policy --format bwrap
```

---

## 4. Running the Test Suite

Run all 51 automated unit, integration, and benchmark tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py"
```

Expected output:
```text
Ran 51 tests in ~0.7s
OK
```
