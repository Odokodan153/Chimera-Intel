import pytest
import json
import time
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

# Import the module to test
from medint import MedicalIntelligence, app

runner = CliRunner()

@pytest.fixture
def medint_instance():
    """Fixture for the MedicalIntelligence class."""
    return MedicalIntelligence(fda_api_key="test_key")

@pytest.fixture
def mock_trials_response():
    """Mock JSON response from ClinicalTrials.gov V2 API."""
    return {
        "studies": [
            {
                "protocolSection": {
                    "identificationModule": {
                        "nctId": "NCT123456",
                        "briefTitle": "Test Trial for New Drug"
                    },
                    "statusModule": {
                        "overallStatus": "Recruiting"
                    },
                    "conditionsModule": {
                        "conditions": ["Testitis"]
                    },
                    "armsInterventionsModule": {
                        "interventions": [
                            {"name": "Placebo"},
                            {"name": "TestDrug"}
                        ]
                    }
                }
            }
        ]
    }

@pytest.fixture
def mock_feedparser_response():
    """Mock parsed response from feedparser."""
    feed = MagicMock()
    feed.bozo = 0
    entry1 = MagicMock()
    entry1.title = "New Outbreak Alert"
    entry1.link = "http://cdc.gov/alert"
    entry1.summary = "A new outbreak."
    # Create a time.struct_time
    entry1.published_parsed = time.struct_time((2023, 10, 27, 10, 0, 0, 4, 300, 0))
    feed.entries = [entry1]
    return feed

@pytest.fixture
def mock_fda_response():
    """Mock JSON response from openFDA."""
    return {
        "results": [
            {
                "recall_number": "D-123-2023",
                "recalling_firm": "Medical Devices Inc.",
                "product_description": "Test Ventilator Model X",
                "reason_for_recall": "Software glitch.",
                "recall_initiation_date": "20230101",
                "status": "Ongoing"
            }
        ]
    }

@patch('requests.Session.get')
def test_monitor_clinical_trials_success(mock_get, medint_instance, mock_trials_response):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_trials_response
    mock_get.return_value = mock_response
    
    results = medint_instance.monitor_clinical_trials("Pfizer", max_trials=1)
    
    assert len(results) == 1
    assert results[0]["nct_id"] == "NCT123456"
    assert results[0]["status"] == "Recruiting"
    assert "TestDrug" in results[0]["interventions"]
    mock_get.assert_called_once_with(
        'https://clinicaltrials.gov/api/v2/studies',
        params={'query.term': 'Pfizer', 'query.field': 'sponsor', 'pageSize': 1, 'format': 'json'},
        timeout=10
    )

@patch('feedparser.parse')
def test_monitor_disease_outbreaks_success(mock_parse, medint_instance, mock_feedparser_response):
    mock_parse.return_value = mock_feedparser_response
    
    results = medint_instance.monitor_disease_outbreaks("cdc_alerts")
    
    assert len(results) == 1
    assert results[0]["title"] == "New Outbreak Alert"
    assert results[0]["source"] == "cdc_alerts"
    assert results[0]["published"] == "2023-10-27T10:00:00" # ISO format
    mock_parse.assert_called_once_with("https://tools.cdc.gov/api/v2/resources/media/132608.rss")

@patch('requests.Session.get')
def test_monitor_medical_supply_chain_success(mock_get, medint_instance, mock_fda_response):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_fda_response
    mock_get.return_value = mock_response
    
    results = medint_instance.monitor_medical_supply_chain("ventilator", max_recalls=1)
    
    assert len(results) == 1
    assert results[0]["recall_number"] == "D-123-2023"
    assert results[0]["recalling_firm"] == "Medical Devices Inc."
    
    expected_params = {
        "search": 'product_description:"ventilator"+OR+reason_for_recall:"ventilator"',
        "limit": 1,
        "api_key": "test_key"
    }
    mock_get.assert_called_once_with('https://api.fda.gov/device/recall.json', params=expected_params, timeout=10)

# --- CLI Tests ---

@patch('medint.MedicalIntelligence.monitor_clinical_trials')
def test_cli_trials(mock_monitor, mock_trials_response):
    mock_monitor.return_value = mock_trials_response["studies"] # Simplified for test
    result = runner.invoke(app, ["trials", "Moderna", "--max", "1"])
    
    assert result.exit_code == 0
    assert "Querying ClinicalTrials.gov" in result.stdout
    assert "NCT123456" in result.stdout # Check if mock data is in output

@patch('medint.MedicalIntelligence.monitor_disease_outbreaks')
def test_cli_outbreaks(mock_monitor):
    mock_monitor.return_value = [{"title": "WHO Alert", "source": "who_news"}]
    result = runner.invoke(app, ["outbreaks", "--source", "who_news"])
    
    assert result.exit_code == 0
    assert "Fetching latest outbreak data from who_news" in result.stdout
    assert "WHO Alert" in result.stdout

@patch('medint.MedicalIntelligence.monitor_medical_supply_chain')
def test_cli_supply_chain(mock_monitor, mock_fda_response):
    mock_monitor.return_value = mock_fda_response["results"]
    result = runner.invoke(app, ["supply-chain", "pacemaker"])
    
    assert result.exit_code == 0
    assert "Querying openFDA" in result.stdout
    assert "D-123-2023" in result.stdout