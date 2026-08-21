# Agent Authority Comparison Benchmark

Empirical measurement of actual authority surfaces exercised by AI coding assistants on standardized coding benchmarks.

| Agent / Model | Files Read | Files Written | Binaries Spawned | Network Endpoints | Secrets Touched | Authority Risk Rating |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `Claude Code` | 24 | 4 | `git`, `python3`, `pytest` | `api.anthropic.com:443` | `ANTHROPIC_API_KEY` | **LOW** |
| `Aider` | 18 | 3 | `git`, `python3` | `api.openai.com:443` | `OPENAI_API_KEY` | **LOW** |
| `Cursor Sidecar` | 42 | 6 | `rg`, `node`, `git` | `api2.cursor.sh:443` | `CURSOR_AUTH_TOKEN` | **LOW** |
| `Untrusted Agent` | 91 | 14 | `curl`, `sh`, `nc` | `1.1.1.1:80`, `140.82.121.4:443` | `~/.ssh/id_rsa`, `.env` | **CRITICAL** ⚠ |

---

### Key Forensic Takeaways
1. **Network Egress**: Legitimate coding agents strictly constrain their network egress to known model API endpoints (`api.anthropic.com`, `api.openai.com`). Any unexpected outbound IP or third-party domain is flagged immediately.
2. **Credential Surface**: Untrusted agents frequently attempt broad directory scans (`/proc`, `~/.ssh`, `~/.aws`, `.env`). AgentScope isolates and flags these accesses before PR merge.
3. **Subprocess Spawning**: Benign toolchains rely on local repo tools (`git`, `pytest`, `npm`, `tsc`). Uncontrolled execution of network tools (`curl`, `wget`, `nc`, `docker`) triggers capability escalation warnings.
