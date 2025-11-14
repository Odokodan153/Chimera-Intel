import pytest
from unittest.mock import patch, MagicMock
import json
from chimera_intel.core.kol_analyzer import run_kol_analysis
from chimera_intel.core.schemas import KOLAnalysisResult, KeyOpinionLeader

@pytest.fixture
def mock_gemini_client():
    """Mocks the GeminiClient and its generate_response method."""
    with patch("chimera_intel.core.kol_analyzer.GeminiClient") as mock_client_class:
        mock_client_instance = mock_client_class.return_value
        
        # Mock the JSON response
        mock_json_response = [
            {
                "rank": 1,
                "name": "Dr. Alex Jensen",
                "description": "Lead AI Researcher at QuantumLeap Inc."
            },
            {
                "rank": 2,
                "name": "Sarah Chen",
                "description": "CEO of FutureSynth and prominent industry analyst."
            }
        ]
        
        # The LLM often returns the JSON as a string, sometimes in a code block
        mock_client_instance.generate_response.return_value = f"```json\n{json.dumps(mock_json_response)}\n```"
        mock_client_instance.model = True  # Simulate successful initialization
        yield mock_client_instance

@pytest.fixture
def mock_google_search():
    """Mocks the google_search function."""
    with patch("chimera_intel.core.kol_analyzer.google_search") as mock_search:
        mock_search.return_value = [
            "https://example.com/article1",
            "https://example.com/article2"
        ]
        yield mock_search

@pytest.fixture
def mock_scrape_text():
    """Mocks the _scrape_text_from_url helper function."""
    with patch("chimera_intel.core.kol_analyzer._scrape_text_from_url") as mock_scrape:
        mock_scrape.side_effect = [
            "Dr. Alex Jensen said...",
            "We interview Sarah Chen about..."
        ]
        yield mock_scrape

def test_run_kol_analysis_success(mock_gemini_client, mock_google_search, mock_scrape_text):
    """
    Tests a successful run of the KOL analyzer.
    """
    industry = "Generative AI"
    result = run_kol_analysis(industry, limit=2)
    
    assert isinstance(result, KOLAnalysisResult)
    assert result.error is None
    assert result.industry_query == industry
    assert result.total_kols_found == 2
    assert len(result.kols) == 2
    
    # Check if the Pydantic models were created correctly
    assert isinstance(result.kols[0], KeyOpinionLeader)
    assert result.kols[0].name == "Dr. Alex Jensen"
    assert result.kols[0].rank == 1
    assert result.kols[1].name == "Sarah Chen"
    
    # Check that search and scrape were called
    mock_google_search.assert_called_once()
    assert mock_scrape_text.call_count == 2
    
    # Check that the LLM was called
    mock_gemini_client.generate_response.assert_called_once()
    prompt_arg = mock_gemini_client.generate_response.call_args[0][0]
    assert industry in prompt_arg
    assert "Dr. Alex Jensen said..." in prompt_arg

def test_run_kol_analysis_no_urls_found(mock_gemini_client, mock_google_search):
    """Tests the scenario where Google search returns no URLs."""
    mock_google_search.return_value = []
    
    result = run_kol_analysis("Niche Topic", limit=2)
    
    assert result.error == "No articles found for this topic."
    assert result.total_kols_found == 0

def test_run_kol_analysis_scrape_failed(mock_gemini_client, mock_google_search, mock_scrape_text):
    """Tests the scenario where all URL scraping fails."""
    mock_scrape_text.side_effect = ["", ""] # Return empty strings
    
    result = run_kol_analysis("Generative AI", limit=2)
    
    assert result.error == "Could not scrape content from any found URLs."
    assert result.total_kols_found == 0

def test_run_kol_analysis_llm_json_decode_error(mock_gemini_client, mock_google_search, mock_scrape_text):
    """Tests the scenario where the LLM returns invalid JSON."""
    mock_gemini_client.generate_response.return_value = "This is not JSON."
    
    result = run_kol_analysis("Generative AI", limit=2)
    
    assert "Failed to parse AI response" in result.error
    assert result.total_kols_found == 0