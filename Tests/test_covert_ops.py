import pytest
from unittest.mock import patch
from typer.testing import CliRunner
from chimera_intel.core.covert_ops import covert_ops_app

runner = CliRunner()


@patch("chimera_intel.core.covert_ops.store_data")
def test_find_hidden_content(mock_store_data):
    """
    Tests the 'find-hidden-content' command simulation.
    """
    result = runner.invoke(
        covert_ops_app, ["find-hidden-content", "example.com"]
    )

    assert result.exit_code == 0
    assert "Simulating hidden content scan on: example.com" in result.stdout
    assert "Discovered Content (Simulated)" in result.stdout
    assert "https://example.com/api" in result.stdout
    assert "https://example.com/admin" in result.stdout
    assert "https://example.com/.env" in result.stdout
    # Check that it called the store_data function
    mock_store_data.assert_called_once()
    assert mock_store_data.call_args[0][0] == "example.com"
    assert mock_store_data.call_args[0][1] == "covert_ops_content"


@patch("chimera_intel.core.covert_ops.store_data")
def test_check_takeover(mock_store_data):
    """
    Tests the 'check-takeover' command simulation.
    """
    result = runner.invoke(
        covert_ops_app, ["check-takeover", "example.com"]
    )

    assert result.exit_code == 0
    assert "Simulating infrastructure takeover check on: example.com" in result.stdout
    assert "Potential Takeover Opportunities (Simulated)" in result.stdout
    assert "blog.example.com" in result.stdout
    assert "sites.github.com" in result.stdout
    assert "GitHub Pages" in result.stdout
    assert "jobs.example.com" in result.stdout
    assert "unclaimed.service.com" in result.stdout
    # Check that it called the store_data function
    mock_store_data.assert_called_once()
    assert mock_store_data.call_args[0][0] == "example.com"
    assert mock_store_data.call_args[0][1] == "covert_ops_takeover"


@patch("chimera_intel.core.covert_ops.store_data")
def test_find_hidden_content_no_findings(mock_store_data):
    """
    Tests the command when no simulated content is "found".
    We can mock the COMMON_PATHS to be different from the hardcoded check.
    """
    with patch("chimera_intel.core.covert_ops.COMMON_PATHS", ["/safe", "/index.html"]):
        result = runner.invoke(
            covert_ops_app, ["find-hidden-content", "safe-example.com"]
        )
    
    assert result.exit_code == 0
    assert "No sensitive hidden paths found from common list." in result.stdout
    mock_store_data.assert_not_called()


@patch("chimera_intel.core.covert_ops.store_data")
def test_check_takeover_no_findings(mock_store_data):
    """
    Tests the command when no simulated takeovers are "found".
    """
    # By default, the mock DNS records are hardcoded in the function.
    # We can patch the TAKEOVER_CNAMES dict to be empty.
    with patch("chimera_intel.core.covert_ops.TAKEOVER_CNAMES", {}):
        result = runner.invoke(
            covert_ops_app, ["check-takeover", "safe-example.com"]
        )
    
    assert result.exit_code == 0
    assert "No obvious takeover opportunities found (simulated)." in result.stdout
    mock_store_data.assert_not_called()