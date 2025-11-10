"""
Tests for the Sales & Intent Intelligence (SALINT) module.
"""

import pytest
from typer.testing import CliRunner
from unittest.mock import patch, AsyncMock, MagicMock
import json

from chimera_intel.core.sales_intel import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def mock_project_and_keys():
    """Mocks essentials for all tests."""
    with patch("chimera_intel.core.sales_intel.resolve_target") as mock_resolve, patch(
        "chimera_intel.core.sales_intel.API_KEYS"
    ) as mock_keys:
        mock_resolve.return_value = "example.com"
        mock_keys.google_api_key = "fake_google_key"
        mock_keys.google_cse_id = "fake_cse_id"
        yield mock_resolve, mock_keys


@patch("chimera_intel.core.sales_intel._search_google_cse", new_callable=AsyncMock)
def test_find_intent_signals_success(mock_search_cse):
    """Tests the 'find-intent-signals' command."""
    # Mock the API response
    mock_search_cse.return_value = {
        "items": [
            {
                "title": "Example.com is hiring Customer Support",
                "link": "https://example.com/jobs/support",
                "snippet": "We are hiring customer support...",
            }
        ]
    }

    result = runner.invoke(app, ["find-intent-signals", "example.com"])

    assert result.exit_code == 0
    assert "Hunting for intent and retention signals" in result.stdout
    assert "Found 1 potential intent/retention signals" in result.stdout
    assert "example.com/jobs/support" in result.stdout

    # Check that our queries were formulated
    assert mock_search_cse.call_count > 0
    first_call_args = mock_search_cse.await_args_list[0].args
    assert '"example.com"' in first_call_args[0]
    assert '"RFP"' in first_call_args[4].args[0]


@patch("chimera_intel.core.sales_intel._search_google_cse", new_callable=AsyncMock)
def test_mine_win_loss_signals_success(mock_search_cse):
    """Tests the 'mine-win-loss' command."""
    # Mock the API response
    mock_search_cse.return_value = {
        "items": [
            {
                "title": "Case Study: How we use Example.com",
                "link": "https://customer.com/case-study-example",
                "snippet": "We love example.com...",
            }
        ]
    }

    result = runner.invoke(app, ["mine-win-loss", "example.com"])

    assert result.exit_code == 0
    assert "Mining win/loss signals" in result.stdout
    assert "Found 1 potential win/loss signals" in result.stdout
    assert "case-study-example" in result.stdout

    # Check that our queries were formulated
    assert mock_search_cse.call_count > 0
    first_call_args = mock_search_cse.await_args_list[0].args
    assert '"case study"' in first_call_args[0]
    assert '"switched from example.com"' in first_call_args[3].args[0]


def test_find_intent_signals_no_keys(mock_project_and_keys):
    """Tests failure when API keys are missing."""
    _mock_resolve, mock_keys = mock_project_and_keys
    mock_keys.google_api_key = None  # Remove key

    result = runner.invoke(app, ["find-intent-signals", "example.com"])

    assert result.exit_code == 1
    assert "Error: 'google_api_key' and 'google_cse_id' must be set." in result.stdout


def test_mine_win_loss_invalid_domain(mock_project_and_keys):
    """Tests failure with an invalid domain."""
    mock_resolve, _mock_keys = mock_project_and_keys
    mock_resolve.return_value = "notadomain"

    with patch(
        "chimera_intel.core.sales_intel.is_valid_domain"
    ) as mock_is_valid:
        mock_is_valid.return_value = False
        result = runner.invoke(app, ["mine-win-loss", "notadomain"])

    assert result.exit_code == 1
    assert "Invalid domain" in result.stdout