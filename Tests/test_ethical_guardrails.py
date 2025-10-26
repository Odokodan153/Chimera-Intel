import pytest
from unittest.mock import patch, mock_open
import json

from src.chimera_intel.core.ethical_guardrails import EthicalGuardrails

# A mock valid framework for testing
MOCK_FRAMEWORK = {
    "principles": {
        "beneficence": "Do good.",
        "non_maleficence": "Do no harm."
    },
    "rules": [
        {
            "id": "RULE-001",
            "category": "privacy",
            "action": "block",
            "keywords": ["social security number", "ssn"]
        },
        {
            "id": "RULE-002",
            "category": "hate_speech",
            "action": "flag",
            "keywords": ["test_hate_word"]
        }
    ]
}

@pytest.fixture
def mock_json_load():
    """Fixture to mock json.load."""
    with patch("json.load") as mock_load:
        mock_load.return_value = MOCK_FRAMEWORK
        yield mock_load

@pytest.fixture
def mock_open_file():
    """Fixture to mock open()."""
    m = mock_open(read_data=json.dumps(MOCK_FRAMEWORK))
    with patch("builtins.open", m):
        yield m

# --- Tests for load_framework ---

def test_load_framework_file_not_found(mock_json_load):
    """Test the guardrails when the framework file is not found."""
    m = mock_open()
    m.side_effect = FileNotFoundError("File not found")
    with patch("builtins.open", m):
        guardrails = EthicalGuardrails()
        assert guardrails.framework == {}
        assert guardrails.is_enabled is False

def test_load_framework_invalid_json(mock_json_load):
    """Test the guardrails when the framework file contains invalid JSON."""
    m = mock_open(read_data="{invalid_json:}")
    with patch("builtins.open", m):
        # Mock json.load to raise JSONDecodeError
        with patch("json.load", side_effect=json.JSONDecodeError("msg", "doc", 0)):
            guardrails = EthicalGuardrails()
            assert guardrails.framework == {}
            assert guardrails.is_enabled is False

def test_load_framework_success(mock_open_file, mock_json_load):
    """Test successful loading of the framework."""
    guardrails = EthicalGuardrails()
    assert guardrails.framework == MOCK_FRAMEWORK
    assert guardrails.is_enabled is True

# --- Tests for assess_prompt ---

@pytest.mark.parametrize("prompt, expected_assessment", [
    # Test RULE-001 (block)
    ("What is your social security number?", 
     (False, "RULE-001", "privacy", "block", "social security number")),
    
    # Test RULE-002 (flag)
    ("This is a test_hate_word.", 
     (False, "RULE-002", "hate_speech", "flag", "test_hate_word")),
    
    # Test a benign prompt
    ("What is the capital of France?", 
     (True, None, None, None, None)),
])
def test_assess_prompt_various_cases(mock_open_file, mock_json_load, prompt, expected_assessment):
    """Test the assess_prompt method with different rules."""
    guardrails = EthicalGuardrails()
    assert guardrails.assess_prompt(prompt) == expected_assessment

def test_assess_prompt_disabled(mock_open_file, mock_json_load):
    """Test assess_prompt when guardrails are disabled."""
    guardrails = EthicalGuardrails()
    guardrails.is_enabled = False # Manually disable
    
    prompt = "What is your social security number?"
    # Should return True (allowed) because the system is disabled
    assert guardrails.assess_prompt(prompt) == (True, None, None, None, None)