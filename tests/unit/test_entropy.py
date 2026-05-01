# Testing calculate entropy math

import pytest
from scanner.engine import ScanEngine

@pytest.mark.parametrize("input_str, expected_min, expected_max", [
    ("", 0, 0.1),                           # Empty
    ("aaaaaaaaaaaaaaaa", 0, 0.5),           # Low entropy (repeated)
    ("xK9#mP2$vL7@nQ4!", 3.5, 5.0),         # High entropy (random)
    ("This is a normal sentence.", 1, 4.0), # Medium entropy (English)
])
def test_calculate_entropy(engine_for, input_str, expected_min, expected_max):
    score = engine_for._calculate_entropy(input_str)
    assert expected_min <= score <= expected_max