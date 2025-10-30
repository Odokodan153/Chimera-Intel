import pytest
from unittest.mock import patch, mock_open
import json

# Ensure the 'src' directory is in the Python path or adjust the import
from src.chimera_intel.core.ethical_guardrails import EthicalFramework

# A mock rules file matching the structure expected by EthicalFramework
MOCK_RULES = {
    "test_rule_1": {
        "description": "A test rule.",
        "keywords": ["test_keyword_1", "test_keyword_2"],
        "severity": "High",
    },
    "test_rule_2": {
        "description": "Another test rule.",
        "keywords": ["test_keyword_3"],
        "severity": "Medium",
    },
}


@pytest.fixture
def mock_open_file():
    """Fixture to mock open() reading the MOCK_RULES."""
    m = mock_open(read_data=json.dumps(MOCK_RULES))
    with patch("builtins.open", m) as mock_file:
        yield mock_file


@pytest.fixture
def mock_json_load():
    """Fixture to mock json.load."""
    with patch("json.load") as mock_load:
        mock_load.return_value = MOCK_RULES
        yield mock_load


# --- Tests for __init__ ---


def test_load_rules_success(mock_open_file, mock_json_load):
    """Test successful loading of rules from a file."""
    filepath = "dummy/path/rules.json"
    guardrails = EthicalFramework(rules_filepath=filepath)

    # Check that open was called with the correct path
    mock_open_file.assert_called_once_with(filepath, "r")
    # Check that json.load was called
    mock_json_load.assert_called_once()
    # Check that the rules are loaded correctly
    assert guardrails.rules == MOCK_RULES


def test_load_rules_file_not_found():
    """Test fallback to default rules when the file is not found."""
    filepath = "non_existent_file.json"
    m = mock_open()
    m.side_effect = FileNotFoundError("File not found")

    # We also need to patch logging to check the error
    with patch("logging.error") as mock_log:
        with patch("builtins.open", m):
            guardrails = EthicalFramework(rules_filepath=filepath)

            # Check if error was logged
            mock_log.assert_called_once()
            # Check that it fell back to default rules
            assert "pressure_tactics" in guardrails.rules
            assert "misrepresentation" in guardrails.rules


def test_load_rules_invalid_json():
    """Test fallback to default rules when the file contains invalid JSON."""
    filepath = "invalid.json"
    m = mock_open(read_data="{invalid_json:}")

    with patch("logging.error") as mock_log:
        with patch("builtins.open", m):
            # Mock json.load to raise JSONDecodeError
            with patch("json.load", side_effect=json.JSONDecodeError("msg", "doc", 0)):
                guardrails = EthicalFramework(rules_filepath=filepath)

                # Check if error was logged
                mock_log.assert_called_once()
                # Check that it fell back to default rules
                assert "pressure_tactics" in guardrails.rules


def test_load_default_rules():
    """Test that default rules are loaded when no filepath is provided."""
    guardrails = EthicalFramework()
    assert "pressure_tactics" in guardrails.rules
    assert "emotional_manipulation" in guardrails.rules
    assert len(guardrails.rules) == 4  # Based on the provided file


# --- Tests for check_message ---


@pytest.fixture
def default_guardrails():
    """Fixture to provide an EthicalFramework instance with default rules."""
    return EthicalFramework()


@pytest.mark.parametrize(
    "message, expected_violation, triggered_by",
    [
        # Test pressure_tactics
        ("This is your last chance to accept!", "pressure_tactics", "last chance"),
        ("You must act now or the deal is gone.", "pressure_tactics", "act now"),
        # Test misrepresentation
        ("Believe me, this is the best you'll get.", "misrepresentation", "believe me"),
        # Test emotional_manipulation
        (
            "You really don't want to let us down, do you?",
            "emotional_manipulation",
            "let us down",
        ),
        (
            "Don't be difficult, just sign.",
            "emotional_manipulation",
            "don't be difficult",
        ),
        # Test information_hiding
        (
            "That's not important right now.",
            "information_hiding",
            "that's not important",
        ),
        # Test a benign message
        ("What is the capital of France?", None, None),
        # Test case sensitivity (should be case-insensitive)
        ("This is your LAST CHANCE.", "pressure_tactics", "last chance"),
    ],
)
def test_check_message_various_cases(
    default_guardrails, message, expected_violation, triggered_by
):
    """Test the check_message method with various default rules."""
    violations = default_guardrails.check_message(message)

    if expected_violation:
        assert len(violations) > 0
        assert violations[0]["violation"] == expected_violation
        assert violations[0]["triggered_by"] == triggered_by
    else:
        assert len(violations) == 0


def test_check_message_multiple_violations(default_guardrails):
    """Test a message that triggers multiple violations."""
    message = (
        "This is your last chance, and to be honest, you'll let us down if you refuse."
    )
    violations = default_guardrails.check_message(message)

    assert len(violations) >= 3  # >= in case keywords overlap
    violation_types = {v["violation"] for v in violations}
    assert "pressure_tactics" in violation_types
    assert "misrepresentation" in violation_types
    assert "emotional_manipulation" in violation_types


def test_check_message_custom_rules(mock_open_file, mock_json_load):
    """Test check_message with custom rules loaded from a file."""
    filepath = "dummy/path/rules.json"
    guardrails = EthicalFramework(rules_filepath=filepath)

    # Test a message that triggers a custom rule
    message = "This contains test_keyword_1."
    violations = guardrails.check_message(message)
    assert len(violations) == 1
    assert violations[0]["violation"] == "test_rule_1"
    assert violations[0]["triggered_by"] == "test_keyword_1"

    # Test a benign message
    message = "This is a benign message."
    violations = guardrails.check_message(message)
    assert len(violations) == 0
