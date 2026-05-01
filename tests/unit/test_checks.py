# individual checks and audit methods

import pytest
import stat
from unittest.mock import patch, MagicMock
from scanner.engine import ScanEngine

# --- Test Sensitive Filenames ---
@pytest.mark.parametrize("filename, should_flag", [
    (".env", True),
    (".env.production", True),
    ("id_rsa", True),
    ("id_rsa.pub", False),  # Public keys are usually okay
    ("server.pem", True),
    ("main.py", False),
])
def test_check_sensitive_filename(engine_for, scan_dir, filename, should_flag):
    # We create the file and see if the engine picks it up
    scan_dir.write_file(filename, "dummy content")
    
    # Note: You'll need to ensure your engine has a _check_sensitive_files method
    # or incorporates this into the main loop.
    findings = engine_for.run_all_checks()
    
    is_flagged = any(f["type"] == "Sensitive File Committed" for f in findings)
    assert is_flagged == should_flag

# --- Test File Permissions (The Mocking Part) ---
def test_audit_file_permissions_vulnerable(engine_for, scan_dir):
    file_path = scan_dir.write_file("insecure.sh", "echo 'hi'")
    
    # We mock os.stat to return a mode that represents 777
    with patch("os.stat") as mock_stat:
        mock_obj = MagicMock()
        # S_IWOTH is world-writable, S_IXOTH is world-executable
        mock_obj.st_mode = stat.S_IFREG | 0o777 
        mock_stat.return_value = mock_obj
        
        findings = engine_for.run_all_checks()
        
    assert any(f["type"] == "Dangerous Permissions" for f in findings)

# --- Test Dependency Auditing ---
def test_audit_dependencies_vulnerable(engine_for, scan_dir):
    # Create a requirements.txt with an old version
    scan_dir.write_file("requirements.txt", "flask==2.1.0")
    
    findings = engine_for.run_all_checks()
    
    assert any("flask" in f["detail"] and "Vulnerable Dependency" in f["type"] for f in findings)

def test_audit_dependencies_safe(engine_for, scan_dir):
    # Create a requirements.txt with a safe version
    scan_dir.write_file("requirements.txt", "flask==2.3.0")
    
    findings = engine_for.run_all_checks()
    
    # Should not find any vulnerability for flask 2.3.0
    assert not any("flask" in f["detail"] for f in findings)