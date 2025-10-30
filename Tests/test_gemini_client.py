import pytest
from unittest.mock import patch, MagicMock
import logging

# Import the class to be tested
from src.chimera_intel.core.gemini_client import GeminiClient


@pytest.fixture
def mock_api_keys():
    """Fixture to mock the API_KEYS object."""
    mock_keys = MagicMock()
    mock_keys.google_api_key = "test_api_key"
    return mock_keys


@pytest.fixture
def mock_genai():
    """Fixture to mock the google.generativeai library."""
    with patch("src.chimera_intel.core.gemini_client.genai") as mock_genai_lib:
        mock_model = MagicMock()
        mock_genai_lib.GenerativeModel.return_value = mock_model
        yield mock_genai_lib, mock_model


# --- Tests for __init__ ---


@patch("src.chimera_intel.core.gemini_client.API_KEYS")
def test_init_no_api_key(mock_keys, caplog):
    """Test client initialization when Google API key is missing."""
    mock_keys.google_api_key = None
    with caplog.at_level(logging.ERROR):
        client = GeminiClient()
        assert client.model is None
        assert "Gemini API key not found in configuration." in caplog.text


@patch("src.chimera_intel.core.gemini_client.API_KEYS")
@patch("src.chimera_intel.core.gemini_client.genai")
def test_init_configure_exception(mock_genai_lib, mock_keys, caplog):
    """Test client initialization when genai.configure raises an exception."""
    mock_keys.google_api_key = "test_key"
    mock_genai_lib.configure.side_effect = Exception("Config failed")
    with caplog.at_level(logging.ERROR):
        client = GeminiClient()
        assert client.model is None
        assert "Failed to configure Gemini client: Config failed" in caplog.text


# --- Tests for classify_intent ---


@patch("src.chimera_intel.core.gemini_client.API_KEYS")
def test_classify_intent_no_model(mock_keys):
    """Test classify_intent when the model failed to initialize."""
    mock_keys.google_api_key = None  # Force model to be None
    client = GeminiClient()
    result = client.classify_intent("Hello")
    assert result == "unknown"


@patch("src.chimera_intel.core.gemini_client.API_KEYS")
def test_classify_intent_api_exception(mock_api_keys, mock_genai, caplog):
    """Test classify_intent when the Gemini API raises an exception."""
    mock_genai_lib, mock_model = mock_genai
    mock_model.generate_content.side_effect = Exception("API Error")

    with patch("src.chimera_intel.core.gemini_client.API_KEYS", mock_api_keys):
        client = GeminiClient()
        with caplog.at_level(logging.ERROR):
            result = client.classify_intent("Test message")
            assert result == "unknown"
            assert "Gemini intent classification failed: API Error" in caplog.text


# --- Tests for generate_response ---


@patch("src.chimera_intel.core.gemini_client.API_KEYS")
def test_generate_response_no_model(mock_keys):
    """Test generate_response when the model failed to initialize."""
    mock_keys.google_api_key = None  # Force model to be None
    client = GeminiClient()
    result = client.generate_response("Test prompt")
    assert result == "I am not available to respond right now."


@patch("src.chimera_intel.core.gemini_client.API_KEYS")
def test_generate_response_api_exception(mock_api_keys, mock_genai, caplog):
    """Test generate_response when the Gemini API raises an exception."""
    mock_genai_lib, mock_model = mock_genai
    mock_model.generate_content.side_effect = Exception("Generation Error")

    with patch("src.chimera_intel.core.gemini_client.API_KEYS", mock_api_keys):
        client = GeminiClient()
        with caplog.at_level(logging.ERROR):
            result = client.generate_response("Test prompt")
            assert (
                result
                == "I am having trouble formulating a response. Could you please rephrase?"
            )
            assert "Gemini response generation failed: Generation Error" in caplog.text
