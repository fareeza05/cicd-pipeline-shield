# Testing regex pattern correctness
import re
import pytest
from scanner.engine import ScanEngine

@pytest.fixture
def signatures():
    # We instantiate the engine just to grab the signature dictionary
    return ScanEngine(".").signatures

@pytest.mark.parametrize("label, text, should_match", [
    # AWS Access Keys
    ("AWS Access Key", "AKIA1234567890ABCDEF", True),
    ("AWS Access Key", "akia1234567890abcdef", False), # Case sensitive
    ("AWS Access Key", "AKIA123", False),              # Too short
    
    # Private Keys
    ("Private Key Block", "-----BEGIN RSA PRIVATE KEY-----", True),
    ("Private Key Block", "-----BEGIN EC PRIVATE KEY-----", True),
    
    # Passwords / Secrets
    ("Potential Password/Secret", 'password = "hunter2"', True),
    ("Potential Password/Secret", 'API_KEY: "12345"', True),
    ("Potential Password/Secret", 'secret: hunter2', True),
    ("Potential Password/Secret", 'passwordless = true', False), # False positive guard
    
    # SSNs
    ("SSN (PII)", "123-45-6789", True),
    ("SSN (PII)", "123-456-789", False), # Wrong segment length
])
def test_regex_patterns(signatures, label, text, should_match):
    pattern = signatures[label]
    match = re.search(pattern, text)
    assert (match is not None) == should_match