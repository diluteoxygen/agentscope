"""
Unit and integration tests for HTML visual report and diff visualizer.
"""

import unittest
import tempfile
from pathlib import Path
from agentscope.models import (
    CapabilityFingerprint,
    Capabilities,
    FilesystemCapabilities,
    RunMetadata,
    RiskLevel
)
from agentscope.diff import diff_fingerprints
from agentscope.visualizer import render_fingerprint_html, render_diff_html
from agentscope.cli import build_parser, cmd_report, cmd_diff


class TestVisualizer(unittest.TestCase):
    def test_render_fingerprint_html(self):
        fp = CapabilityFingerprint(
            metadata=RunMetadata(
                agent="claude",
                command=["claude", "code"],
                timestamp="2026-08-21T12:00:00Z",
                duration_ms=4500,
                exit_code=0,
                cwd="/repo",
                hostname="dev-host",
            ),
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/app.py"], write=["./build/bundle.js"]),
                commands=["git", "npm"],
                network=["api.anthropic.com:443"],
                secrets=["env:ANTHROPIC_API_KEY"]
            )
        )

        html_out = render_fingerprint_html(fp, title="Test Report")
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("Test Report", html_out)
        self.assertIn("claude", html_out)
        self.assertIn("./src/app.py", html_out)
        self.assertIn("./build/bundle.js", html_out)
        self.assertIn("api.anthropic.com:443", html_out)
        self.assertIn("env:ANTHROPIC_API_KEY", html_out)

    def test_render_diff_html(self):
        base = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(read=["./src/app.py"]),
                commands=["git"]
            )
        )
        cand = CapabilityFingerprint(
            capabilities=Capabilities(
                filesystem=FilesystemCapabilities(
                    read=["./src/app.py"],
                    write=[".github/workflows/deploy.yml"]
                ),
                commands=["git", "curl"],
                secrets=["env:AWS_SECRET_ACCESS_KEY"]
            )
        )
        delta = diff_fingerprints(base, cand)
        html_diff = render_diff_html(delta, title="Test Diff")

        self.assertIn("<!DOCTYPE html>", html_diff)
        self.assertIn("Test Diff", html_diff)
        self.assertIn("badge-critical", html_diff)
        self.assertIn("env:AWS_SECRET_ACCESS_KEY", html_diff)
        self.assertIn(".github/workflows/deploy.yml", html_diff)

    def test_cli_html_export(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            fp_path = tmp_path / "run.json"
            html_out = tmp_path / "report.html"

            fp = CapabilityFingerprint(
                capabilities=Capabilities(
                    filesystem=FilesystemCapabilities(read=["./src/index.ts"])
                )
            )
            fp_path.write_text(fp.to_json())

            parser = build_parser()
            args = parser.parse_args(["view", str(fp_path), "--html", str(html_out)])
            rc = cmd_report(args)
            self.assertEqual(rc, 0)
            self.assertTrue(html_out.exists())
            self.assertIn("<!DOCTYPE html>", html_out.read_text())


if __name__ == "__main__":
    unittest.main()
