import pytest
import os
import json
import yaml
import time
from unittest.mock import patch, MagicMock
from cryptography.fernet import Fernet
import unittest
import base64
from collections import namedtuple

# Import the functions to be tested
from chimera_intel.core.security_utils import (
    audit_event,
    _first_n,
    normalize_ai_result,
    redact_personal_data,
    load_consent,
    check_consent_for_action
)

# --- Fixtures ---

@pytest.fixture
def valid_consent_dict():
    """A valid, in-memory consent dictionary for testing."""
    return {
        "id": "consent-test-001",
        "authorized_targets": ["example.com", "test.org"],
        "authorized_actions": ["phishing", "ttp", "ttp_analysis"],
        "valid_from_epoch": int(time.time()) - 3600,  # 1 hour ago
        "valid_to_epoch": int(time.time()) + 3600,    # 1 hour from now
    }

@pytest.fixture
def tmp_consent_files(tmp_path):
    """Creates temporary YAML and JSON consent files."""
    data = {
        "id": "file-consent-002",
        "authorized_targets": ["file.com"],
        "authorized_actions": ["phishing"]
    }
    
    # Create YAML file
    yaml_file = tmp_path / "consent.yaml"
    with open(yaml_file, 'w') as f:
        yaml.dump(data, f)
        
    # Create JSON file
    json_file = tmp_path / "consent.json"
    with open(json_file, 'w') as f:
        json.dump(data, f)
        
    # Create invalid file
    txt_file = tmp_path / "consent.txt"
    txt_file.write_text("invalid format")
        
    return namedtuple("ConsentFiles", ["yaml", "json", "txt"])(yaml_file, json_file, txt_file)


# --- Test Cases ---

@patch('chimera_intel.core.security_utils.audit_logger.info')
def test_audit_event(mock_logger_info):
    """Test that audit_event formats and logs the correct JSON message."""
    test_user = "test_user"
    test_action = "test_action"
    test_target = "example.com"
    test_consent_id = "consent-001"
    
    audit_event(test_user, test_action, test_target, test_consent_id, note="A test note")
    
    # Check that the logger was called
    mock_logger_info.assert_called_once()
    
    # Get the string argument passed to the logger
    log_message = mock_logger_info.call_args[0][0]
    
    # Parse the JSON log and check its contents
    log_data = json.loads(log_message)
    
    assert log_data["user"] == test_user
    assert log_data["action"] == test_action
    assert log_data["target"] == test_target
    assert log_data["consent_id"] == test_consent_id
    assert log_data["note"] == "A test note"
    assert "timestamp" in log_data

@pytest.mark.parametrize("sample, n, expected", [
    ([1, 2, 3, 4, 5, 6], 3, [1, 2, 3]),
    ([1, 2], 5, [1, 2]),
    ({"a": 10, "b": 20, "c": 30}, 2, [10, 20]),
    (None, 5, []),
    ([], 3, []),
    ({}, 3, []),
])
def test_first_n(sample, n, expected):
    """Test the _first_n helper for safely slicing lists and dicts."""
    assert _first_n(sample, n) == expected

@pytest.mark.parametrize("ai_result, expected_error, expected_text", [
    ({"analysis_text": "hello"}, None, "hello"),
    ({"error": "AI failed"}, "AI failed", ""),
    ({"content": "world", "err": "uh oh"}, "uh oh", "world"),
    (None, "AI returned None", ""),
    ({"unrelated": "data"}, None, ""),
])
def test_normalize_ai_result_dict(ai_result, expected_error, expected_text):
    """Test normalize_ai_result with dictionary inputs."""
    err, text = normalize_ai_result(ai_result)
    assert err == expected_error
    assert text == expected_text

def test_normalize_ai_result_object():
    """Test normalize_ai_result with a mock Pydantic-style object."""
    MockResult = namedtuple("MockResult", ["analysis_text", "error"])
    ai_result = MockResult(analysis_text="from object", error="object error")
    
    err, text = normalize_ai_result(ai_result)
    assert err == "object error"
    assert text == "from object"

def test_normalize_ai_result_fallback_str():
    """Test normalize_ai_result fallback to str() for unknown types."""
    class UnknownObject:
        def __str__(self):
            return "unknown object string"

    ai_result = UnknownObject()
    err, text = normalize_ai_result(ai_result)
    assert err is None
    assert text == "unknown object string"

@pytest.mark.parametrize("input_text, expected_output", [
    ("My email is test@example.com.", "My email is [REDACTED]."),
    ("Call +1234567890 for help.", "Call [REDACTED] for help."),
    ("A mix: foo@bar.com and +987654321.", "A mix: [REDACTED] and [REDACTED]."),
    ("Safe text with no PII.", "Safe text with no PII."),
    ("Short phone 555-1212", "Short phone 555-1212"), # Assumes 7-digit minimum
    ("Long phone +123456789012345", "Long phone [REDACTED]"),
    (None, None),
    ("", ""),
])
def test_redact_personal_data(input_text, expected_output):
    """Test PII redaction for emails and phone numbers."""
    assert redact_personal_data(input_text) == expected_output

def test_load_consent(tmp_consent_files):
    """Test loading of valid YAML and JSON consent files."""
    yaml_data = load_consent(str(tmp_consent_files.yaml))
    assert yaml_data["id"] == "file-consent-002"
    assert "phishing" in yaml_data["authorized_actions"]
    
    json_data = load_consent(str(tmp_consent_files.json))
    assert json_data["id"] == "file-consent-002"
    assert "phishing" in json_data["authorized_actions"]

def test_load_consent_invalid_file(tmp_consent_files):
    """Test that loading an invalid file type raises a ValueError."""
    with pytest.raises(ValueError, match="Consent file must be a .json, .yaml, or .yml file."):
        load_consent(str(tmp_consent_files.txt))

def test_load_consent_file_not_found():
    """Test that a missing file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_consent("non_existent_file.yaml")

def test_check_consent_for_action_valid(valid_consent_dict):
    """Test a fully valid consent check."""
    assert check_consent_for_action(valid_consent_dict, "example.com", "phishing") == True
    assert check_consent_for_action(valid_consent_dict, "test.org", "ttp") == True

def test_check_consent_for_action_invalid_target(valid_consent_dict):
    """Test that an unauthorized target fails."""
    assert check_consent_for_action(valid_consent_dict, "unauthorized.com", "phishing") == False

def test_check_consent_for_action_invalid_action(valid_consent_dict):
    """Test that an unauthorized action fails."""
    assert check_consent_for_action(valid_consent_dict, "example.com", "scan") == False

def test_check_consent_for_action_wildcard_target(valid_consent_dict):
    """Test that a wildcard target '*' works."""
    valid_consent_dict["authorized_targets"] = ["*"]
    assert check_consent_for_action(valid_consent_dict, "anything.com", "phishing") == True
    assert check_consent_for_action(valid_consent_dict, "example.com", "phishing") == True

def test_check_consent_for_action_time_expired(valid_consent_dict):
    """Test that an expired consent (valid_to) fails."""
    valid_consent_dict["valid_to_epoch"] = int(time.time()) - 100 # Expired 100s ago
    assert check_consent_for_action(valid_consent_dict, "example.com", "phishing") == False

def test_check_consent_for_action_time_not_yet_valid(valid_consent_dict):
    """Test that a future consent (valid_from) fails."""
    valid_consent_dict["valid_from_epoch"] = int(time.time()) + 100 # Valid in 100s
    assert check_consent_for_action(valid_consent_dict, "example.com", "phishing") == False

def test_check_consent_for_action_no_time_window(valid_consent_dict):
    """Test that consent with no time window is valid."""
    del valid_consent_dict["valid_from_epoch"]
    del valid_consent_dict["valid_to_epoch"]
    assert check_consent_for_action(valid_consent_dict, "example.com", "phishing") == True

# Generate a valid Fernet key for testing
TEST_KEY = Fernet.generate_key().decode()

# Mock API_KEYS before importing the module
mock_api_keys = MagicMock()
mock_api_keys.pii_encryption_key = TEST_KEY

# We patch the config loader *before* the module is imported
with patch("chimera_intel.core.security_utils.API_KEYS", mock_api_keys):
    from chimera_intel.core.security_utils import (
        encrypt_pii, 
        decrypt_pii, 
        get_pii_encryption_key,
        _get_fernet,
    )
    # We need to be able to reset the global singleton
    from chimera_intel.core import security_utils as su

class TestSecurityUtils(unittest.TestCase):

    def setUp(self):
        # Reset the singleton instance before each test
        su._FERNET_INSTANCE = None

    @patch("chimera_intel.core.security_utils.API_KEYS")
    def test_encrypt_decrypt_roundtrip(self, mock_keys):
        """Tests that encrypting and decrypting data returns the original."""
        mock_keys.pii_encryption_key = TEST_KEY
        
        original_text = "This is my secret PII: user@example.com"
        
        encrypted_data = encrypt_pii(original_text)
        self.assertIsInstance(encrypted_data, bytes)
        self.assertNotEqual(encrypted_data, original_text.encode())
        
        decrypted_text = decrypt_pii(encrypted_data)
        self.assertEqual(decrypted_text, original_text)

    @patch("chimera_intel.core.security_utils.API_KEYS")
    def test_get_key_success(self, mock_keys):
        """Tests that the key is retrieved successfully."""
        mock_keys.pii_encryption_key = TEST_KEY
        key = get_pii_encryption_key()
        self.assertEqual(key, TEST_KEY)

    @patch("chimera_intel.core.security_utils.API_KEYS")
    def test_get_key_missing(self, mock_keys):
        """Tests that a missing key raises a ValueError."""
        mock_keys.pii_encryption_key = None
        with self.assertRaises(ValueError) as e:
            get_pii_encryption_key()
        self.assertIn("not set in config", str(e.exception))

    @patch("chimera_intel.core.security_utils.API_KEYS")
    def test_get_key_invalid_base64(self, mock_keys):
        """Tests that an invalid base64 key raises a ValueError."""
        mock_keys.pii_encryption_key = "not-a-real-base64-key!"
        with self.assertRaises(ValueError) as e:
            get_pii_encryption_key()
        self.assertIn("not a valid URL-safe base64 key", str(e.exception))
        
    @patch("chimera_intel.core.security_utils.API_KEYS")
    def test_get_key_wrong_length(self, mock_keys):
        """Tests that a key of the wrong byte length raises a ValueError."""
        # This is a valid base64 key, but not 32 bytes
        wrong_len_key = base64.urlsafe_b64encode(b"12345").decode()
        mock_keys.pii_encryption_key = wrong_len_key
        with self.assertRaises(ValueError) as e:
            get_pii_encryption_key()
        self.assertIn("must be a 32-byte key", str(e.exception))

    @patch("chimera_intel.core.security_utils.API_KEYS")
    def test_encryption_fails_with_no_key(self, mock_keys):
        """Tests that encrypt_pii fails if no key is configured."""
        mock_keys.pii_encryption_key = None
        with self.assertRaises(ValueError) as e:
            encrypt_pii("some data")
        # This error comes from _get_fernet() -> get_pii_encryption_key()
        self.assertIn("not set in config", str(e.exception))

    @patch("chimera_intel.core.security_utils.API_KEYS")
    def test_decryption_fails_with_wrong_key(self, mock_keys):
        """Tests that decryption fails if the key is wrong."""
        # Encrypt with one key
        mock_keys.pii_encryption_key = TEST_KEY
        encrypted_data = encrypt_pii("some data")
        
        # Reset singleton and try to decrypt with a different key
        su._FERNET_INSTANCE = None
        
        wrong_key = Fernet.generate_key().decode()
        mock_keys.pii_encryption_key = wrong_key
        
        with self.assertRaises(ValueError) as e:
            decrypt_pii(encrypted_data)
        self.assertIn("Invalid token or key", str(e.exception))
        
    def test_decrypt_invalid_token(self):
        """Tests decryption with data that is not valid Fernet data."""
        with patch("chimera_intel.core.security_utils.API_KEYS.pii_encryption_key", TEST_KEY):
            with self.assertRaises(ValueError) as e:
                decrypt_pii(b"this is just plain bytes")
            self.assertIn("Invalid token or key", str(e.exception))