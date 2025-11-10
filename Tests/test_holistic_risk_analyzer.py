import pytest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from chimera_intel.core.holistic_risk_analyzer import risk_app

runner = CliRunner()

@pytest.fixture
def mock_db_data():
    """Fixture for aggregated data from the database."""
    return {
        "target": "TestCorp",
        "modules": {
            "corporate_sec_filings": {
                "filing_url": "http://example.com/10-k",
                "risk_factors_summary": "We face significant market risks.",
                "error": None
            },
            "reputation_model": {
                "query": "TestCorp scandal",
                "media_file": "news.jpg",
                "media_synthetic_confidence": 0.8,
                "amplification_network_strength": 60.0,
                "projected_impact_score": 6.5, # High risk
                "risk_level": "High",
                "projected_impact_timeline": [6.0, 5.5, 5.0, 4.5, 4.0, 3.5, 3.0],
                "error": None
            },
            "corporate_regulatory": {
                "total_spent": 2500000, # High spend
                "records": [
                    {"issue": "Data Privacy Bill", "amount": 2500000, "year": 2024}
                ],
                "error": None
            }
        }
    }

@patch('chimera_intel.core.holistic_risk_analyzer.get_aggregated_data_for_target')
def test_holistic_risk_analyzer_success(mock_get_data, mock_db_data):
    """Tests the 'run' command with mock data from various modules."""
    
    mock_get_data.return_value = mock_db_data
    
    output_file = "test_risk_output.json"
    
    result = runner.invoke(
        risk_app,
        [
            "run",
            "TestCorp",
            "--output", output_file
        ],
    )

    assert result.exit_code == 0
    assert "Holistic Risk Profile for: TestCorp" in result.stdout
    assert "Risk Level: High" in result.stdout # Should be high based on scores
    assert "Financial" in result.stdout
    assert "Risk factors identified" in result.stdout
    assert "Reputation" in result.stdout
    assert "Active reputation attack model found" in result.stdout
    assert "Legal" in result.stdout
    assert "Significant lobbying spend" in result.stdout

    # Check that the output file was created
    try:
        with open(output_file, 'r') as f:
            data = json.load(f)
            assert data["target"] == "TestCorp"
            assert data["overall_risk_score"] > 5.0
            assert data["risk_level"] == "High"
            assert len(data["risk_components"]) == 4
    finally:
        # Clean up the created file
        import os
        if os.path.exists(output_file):
            os.remove(output_file)

@patch('chimera_intel.core.holistic_risk_analyzer.get_aggregated_data_for_target')
def test_holistic_risk_analyzer_no_data(mock_get_data):
    """Tests the 'run' command when no data is found for the target."""
    
    mock_get_data.return_value = None # No data
    
    result = runner.invoke(
        risk_app,
        [
            "run",
            "NonExistentCorp"
        ],
    )

    assert result.exit_code == 1
    assert "Error" in result.stdout
    assert "No historical data found" in result.stdout