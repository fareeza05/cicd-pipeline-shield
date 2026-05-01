# Run all checks per-feature end-to-end

import pytest
import os
from scanner.engine import ScanEngine

def test_shieldignore_exclusion(scan_dir):
    """Verifies that files in ignored directories are NOT scanned."""
    # 1. Setup: Create an ignored directory and put a 'secret' inside
    scan_dir.write_file("ignored_dir/secret.txt", "AKIA1234567890ABCDEF")
    scan_dir.write_file(".shieldignore", "ignored_dir")
    
    # 2. Run scan
    engine = ScanEngine(str(scan_dir.path))
    findings = engine.run_all_checks()
    
    # 3. Assert: The leak should be ignored
    assert len(findings) == 0

def test_default_exclusions(scan_dir):
    """Ensures venv and .git are skipped by default even without .shieldignore."""
    scan_dir.write_file("venv/secret.txt", "AKIA1234567890ABCDEF")
    
    engine = ScanEngine(str(scan_dir.path))
    findings = engine.run_all_checks()
    
    assert len(findings) == 0

def test_high_entropy_detection_end_to_end(scan_dir):
    """Verifies that a random string flags a High-Entropy finding."""
    # 26 unique chars → entropy = log2(26) ≈ 4.70, above the engine's 4.5 threshold
    scan_dir.write_file("random.txt", "aB3cD4eF5gH6iJ7kL8mN9oP0qR")
    
    engine = ScanEngine(str(scan_dir.path))
    findings = engine.run_all_checks()
    
    assert any(f["type"] == "High-Entropy String (Potential Key)" for f in findings)

def test_multiple_findings_in_one_file(scan_dir):
    """Ensures multiple distinct leaks in one file are all reported."""
    content = (
        "password = 'first_secret'\n"
        "AKIA1111111111111111\n"
        "AKIA2222222222222222\n"
    )
    scan_dir.write_file("multi_leak.txt", content)
    
    engine = ScanEngine(str(scan_dir.path))
    findings = engine.run_all_checks()
    
    # Expecting at least 3 findings
    assert len(findings) >= 3