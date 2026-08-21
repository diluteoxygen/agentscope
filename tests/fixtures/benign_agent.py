"""
Synthetic benign coding agent fixture.
Performs standard code inspection and writes a test file within the repo workspace.
"""

import sys
import os
from pathlib import Path

def main():
    workspace = Path.cwd()
    
    # 1. Read existing source file
    readme = workspace / "README.md"
    if readme.exists():
        _ = readme.read_text()

    # 2. Write a workspace test file
    test_out = workspace / "tests" / "test_simulated_feature.py"
    test_out.parent.mkdir(parents=True, exist_ok=True)
    test_out.write_text("# Auto-generated test\ndef test_ok(): assert True\n")

    # 3. Read it back
    _ = test_out.read_text()
    
    print("[benign_agent] Successfully inspected code and wrote test.")

if __name__ == "__main__":
    main()
