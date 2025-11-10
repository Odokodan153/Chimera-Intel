"""
Tests for the Internal Analytics (INTA) simulation module.
"""

import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from chimera_intel.core.schemas import AIGenericAnalysisResult

from chimera_intel.core.internal_analytics import app

runner = CliRunner()


@pytest.fixture
def mock_project_and_db():
    """Mocks essentials for all tests."""
    with patch(
        "chimera_intel.core.internal_analytics.resolve_target"
    ) as mock_resolve, patch(
        "chimera_intel.core.internal_analytics.get_aggregated_data_for_target"
    ) as mock_get_data:
        mock_resolve.return_value = "example.com"
        yield mock_resolve, mock_get_data


def test_correlate_proxies_success(mock_project_and_db):
    """Tests 'correlate-proxies' with full data."""
    _mock_resolve, mock_get_data = mock_project_and_db
    mock_get_data.return_value = {
        "target": "example.com",
        "modules": {
            "channel_intel": {
                "traffic_mix_overview": {"Direct": 0.5, "Social": 0.3},
                "potential_partners": [
                    {"partner_page": "http://affiliate.com/review"}
                ],
            },
            "voc_intel": {"total_reviews_analyzed": 150},
        },
    }

    result = runner.invoke(app, ["correlate-proxies"])

    assert result.exit_code == 0
    assert "Correlating conversion proxies" in result.stdout
    assert "Top source: Direct" in result.stdout
    assert "Found 1 potential affiliate/UTM patterns" in result.stdout
    assert "Found App install/review activity: 150 reviews" in result.stdout
    assert "Errors" not in result.stdout


def test_correlate_proxies_partial_data(mock_project_and_db):
    """Tests 'correlate-proxies' with missing data."""
    _mock_resolve, mock_get_data = mock_project_and_db
    mock_get_data.return_value = {
        "target": "example.com",
        "modules": {"channel_intel": {"potential_partners": []}},
    }

    result = runner.invoke(app, ["correlate-proxies"])

    assert result.exit_code == 0
    assert "No affiliate/UTM partner data found" in result.stdout
    assert "Missing 'voc_intel' data" in result.stdout


def test_correlate_proxies_no_data(mock_project_and_db):
    """Tests 'correlate-proxies' when no scans exist."""
    _mock_resolve, mock_get_data = mock_project_and_db
    mock_get_data.return_value = None  # No data in DB

    result = runner.invoke(app, ["correlate-proxies"])

    assert result.exit_code == 1
    assert "No aggregated data found" in result.stdout


@patch(
    "chimera_intel.core.internal_analytics.generate_swot_from_data"
)
@patch("chimera_intel.core.internal_analytics.API_KEYS")
def test_score_leads_success(mock_keys, mock_gen_ai, mock_project_and_db):
    """Tests 'score-leads' AI summary generation."""
    _mock_resolve, mock_get_data = mock_project_and_db
    mock_keys.google_api_key = "fake_google_key"
    mock_get_data.return_value = {
        "target": "example.com",
        "modules": {
            "sales_intel": {
                "signals_found": [
                    {"source_query": "RFP", "title": "Example.com RFP"}
                ]
            }
        },
    }
    mock_gen_ai.return_value = AIGenericAnalysisResult(
        analysis_text="**Lead Score:** Hot\nJustification: Found an RFP."
    )

    result = runner.invoke(app, ["score-leads"])

    assert result.exit_code == 0
    assert "AI-Generated Lead Scoring" in result.stdout
    assert "Lead Score:** Hot" in result.stdout
    
    # Check that the prompt was correct
    mock_gen_ai.assert_called_once()
    prompt_arg = mock_gen_ai.call_args[0][0]
    assert "sales_intel" in prompt_arg
    assert "RFP" in prompt_arg
    assert "generate a lead scoring summary" in prompt_arg


@patch("chimera_intel.core.internal_analytics.API_KEYS")
def test_score_leads_no_key(mock_keys, mock_project_and_db):
    """Tests 'score-leads' when AI key is missing."""
    mock_keys.google_api_key = None  # No key

    result = runner.invoke(app, ["score-leads"])

    assert result.exit_code == 1
    assert "Error: 'google_api_key' must be set" in result.stdout