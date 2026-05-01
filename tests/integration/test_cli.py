# subprocess CLI + exit codes + report file
import pytest
import os
import json

def test_cli_clean_run(scan_dir, run_cli):
    """Verifies that an empty directory returns Exit 0 and a 'PASSED' report."""
    # Setup: Empty directory
    
    # Execution
    ret_code, stdout, report = run_cli(scan_dir.path)
    
    # Assertions
    assert ret_code == 0
    assert "SCAN PASSED" in stdout
    assert report["scan_status"] == "PASSED"
    assert report["total_issues"] == 0

def test_cli_vulnerable_run(scan_dir, run_cli):
    """Verifies that finding a leak returns Exit 1 and a 'FAILED' report."""
    # Setup: Create a leak
    scan_dir.write_file("emergency.txt", "AKIA1234567890ABCDEF")
    
    # Execution
    ret_code, stdout, report = run_cli(scan_dir.path)
    
    # Assertions
    assert ret_code == 1
    assert "SCAN FAILED" in stdout
    assert report["scan_status"] == "FAILED"
    assert report["total_issues"] >= 1
    assert "AWS Access Key" in str(report["findings"])

def test_cli_invalid_path(run_cli):
    """Verifies that a fake path returns Exit 2 (tool error) and an error message."""
    ret_code, stdout, _ = run_cli("/tmp/path/does/not/exist/at/all/12345")

    assert ret_code == 2
    assert "ERROR" in stdout