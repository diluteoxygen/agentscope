"""
Unit and integration tests for Git safety hooks.
"""

import unittest
import tempfile
import stat
import subprocess
from pathlib import Path
from agentscope.hooks import install_git_hooks, uninstall_git_hooks, check_git_hooks_status
from agentscope.cli import build_parser, cmd_hook


class TestGitHooks(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self.tmpdir.name)
        # Initialize a dummy git repo
        subprocess.run(["git", "init", str(self.repo_dir)], capture_output=True, check=True)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_install_and_status_hooks(self):
        res = install_git_hooks(repo_dir=str(self.repo_dir), hook_types=["pre-commit", "pre-push"])
        self.assertTrue(res["pre-commit"])
        self.assertTrue(res["pre-push"])

        hook_file = self.repo_dir / ".git" / "hooks" / "pre-commit"
        self.assertTrue(hook_file.exists())
        self.assertIn("agentscope-hook", hook_file.read_text())
        
        # Check executable bit
        is_exec = bool(hook_file.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        self.assertTrue(is_exec)

        # Check status
        status = check_git_hooks_status(repo_dir=str(self.repo_dir))
        self.assertTrue(status["pre-commit"])
        self.assertTrue(status["pre-push"])

    def test_uninstall_hooks(self):
        install_git_hooks(repo_dir=str(self.repo_dir), hook_types=["pre-commit"])
        un_res = uninstall_git_hooks(repo_dir=str(self.repo_dir), hook_types=["pre-commit"])
        self.assertTrue(un_res["pre-commit"])

        hook_file = self.repo_dir / ".git" / "hooks" / "pre-commit"
        self.assertFalse(hook_file.exists())

    def test_cli_hook_subcommand(self):
        parser = build_parser()
        
        # Test install command
        args_inst = parser.parse_args(["hook", "install", "--type", "all"])
        # We can't change cwd easily without side effects, but parser validation works
        self.assertEqual(args_inst.subcommand, "hook")
        self.assertEqual(args_inst.hook_action, "install")


if __name__ == "__main__":
    unittest.main()
