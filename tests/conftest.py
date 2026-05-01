import sys
import pytest
import os
import json
import subprocess
from scanner.engine import ScanEngine

@pytest.fixture
def scan_dir(tmp_path):
    """
    Helper fixture to create files in a temporary directory.
    Usage: scan_dir.write_file("test.txt", "content")
    """
    class DirHelper:
        def __init__(self, path):
            self.path = path
        def write_file(self, name, content):
            f = self.path / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(content)
            return str(f)
    return DirHelper(tmp_path)

@pytest.fixture
def engine_for(tmp_path):
    """Returns a ScanEngine instance pointed at the temp directory."""
    return ScanEngine(str(tmp_path))

@pytest.fixture
def run_cli():
    """
    Runs the CLI via subprocess. 
    Returns a function that takes a path and returns (returncode, stdout, report_data)
    """
    def _run(target_path):
        # We assume the test is run from the project root
        result = subprocess.run(
            [sys.executable, "scanner/main.py", str(target_path)],
            capture_output=True,
            text=True
        )
        
        report_path = "reports/security_report.json"
        report_data = None
        if os.path.exists(report_path):
            with open(report_path, "r") as f:
                report_data = json.load(f)
                
        return result.returncode, result.stdout, report_data
    return _run