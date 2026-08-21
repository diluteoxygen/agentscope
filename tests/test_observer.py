"""
Unit and integration tests for TraceObserver and strace log parsing.
"""

import unittest
import tempfile
import sys
from pathlib import Path
from agentscope.observer import TraceObserver, parse_strace_output
from agentscope.sni import extract_tls_sni
from tests.test_sni import build_synthetic_client_hello


class TestObserver(unittest.TestCase):
    def test_parse_strace_synthetic_lines(self):
        # Build synthetic TLS Client Hello for registry.npmjs.org
        raw_tls = build_synthetic_client_hello("registry.npmjs.org")
        escaped_tls = "".join(f"\\x{b:02x}" for b in raw_tls)

        lines = [
            '[pid 1001] execve("/usr/bin/git", ["git", "status"], 0x7ffd...) = 0',
            '[pid 1001] openat(AT_FDCWD, "/repo/src/main.py", O_RDONLY|O_CLOEXEC) = 3',
            '[pid 1002] openat(AT_FDCWD, "/repo/src/out.txt", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 4',
            '[pid 1002] creat("/repo/created.txt", 0644) = 5',
            '[pid 1002] unlink("/repo/old.txt") = 0',
            '[pid 1002] unlinkat(AT_FDCWD, "/repo/old2.txt", 0) = 0',
            '[pid 1003] rename("/repo/temp.txt", "/repo/final.txt") = 0',
            '[pid 1004] connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("140.82.121.4")}, 16) = 0',
            '[pid 1005] connect(3, {sa_family=AF_INET6, sin6_port=htons(8080), inet_pton(AF_INET6, "2606:4700::6810:db53", &sin6_addr)}, 28) = 0',
            f'[pid 1006] sendto(3, "{escaped_tls}", 512, 0, NULL, 0) = 512',
        ]

        reads, writes, cmds, net = parse_strace_output(lines)

        self.assertIn("/usr/bin/git", cmds)
        self.assertIn("/repo/src/main.py", reads)
        self.assertIn("/repo/temp.txt", reads)
        self.assertIn("/repo/src/out.txt", writes)
        self.assertIn("/repo/created.txt", writes)
        self.assertIn("/repo/old.txt", writes)
        self.assertIn("/repo/old2.txt", writes)
        self.assertIn("/repo/final.txt", writes)
        self.assertTrue(any("443" in n for n in net))
        self.assertTrue(any("8080" in n for n in net))
        self.assertIn("registry.npmjs.org:443", net)

    def test_live_trace_execution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            obs = TraceObserver(cwd=str(tmp_path))

            script = (
                "import os\n"
                "with open('output.txt', 'w') as f:\n"
                "    f.write('test-data')\n"
                "with open('output.txt', 'r') as f:\n"
                "    _ = f.read()\n"
            )

            cmd = [sys.executable, "-c", script]
            fp, code = obs.trace_command(cmd, agent_name="test-agent")

            self.assertEqual(code, 0)
            self.assertEqual(fp.metadata.agent, "test-agent")
            self.assertEqual(fp.metadata.exit_code, 0)

            # Check that output.txt was recorded in writes and reads
            self.assertIn("./output.txt", fp.capabilities.filesystem.write)
            self.assertIn("./output.txt", fp.capabilities.filesystem.read)


if __name__ == "__main__":
    unittest.main()
