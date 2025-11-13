import pytest
import httpx
from typer.testing import CliRunner
from unittest.mock import MagicMock, patch

from chimera_intel.core.climaint import climaint_app
from chimera_intel.core.schemas import AiCoreResult

runner = CliRunner()

# Mock data fixtures
@pytest.fixture
def mock_wb_stability():
    return [
        {"page": 1, "pages": 1, "per_page": 1, "total": 1},
        [
            {
                "indicator": {"id": "PV.PER.ALL.Z", "value": "Political Stability..."},
                "country": {"id": "CL", "value": "Chile"},
                "date": "2023",
                "value": 45.0,
            }
        ],
    ]

@pytest.fixture
def mock_wb_climate_risk():
    return [
        {"page": 1, "pages": 1, "per_page": 1, "total": 1},
        [
            {
                "indicator": {"id": "AG.LND.EL5M.ZS", "value": "Land area below 5m..."},
                "country": {"id": "CL", "value": "Chile"},
                "date": "2020",
                "value": 0.5,
            }
        ],
    ]

@pytest.fixture
def mock_comtrade():
    return {
        "dataset": [
            {
                "rgDesc": "Imports",
                "TradeValue": "1500000",
                "rtTitle": "Chile",
                "cmdDesc": "Lithium carbonates",
            },
            {
                "rgDesc": "Exports",
                "TradeValue": "250000000",
                "rtTitle": "Chile",
                "cmdDesc": "Lithium carbonates",
            },
        ]
    }

@pytest.fixture
def mock_ai_result():
    return AiCoreResult(
        analysis_text="This is a mock strategic report about Chile and Lithium."
    )


def test_climaint_report_success(
    mocker, mock_wb_stability, mock_wb_climate_risk, mock_comtrade, mock_ai_result
):
    """
    Test the 'climaint report' command successfully.
    """
    # Mock httpx.Client
    mock_http_client = MagicMock()
    
    # Set up multiple responses for the client
    mock_http_client.get.side_effect = [
        # 1st call (Political Stability)
        MagicMock(status_code=200, json=lambda: mock_wb_stability),
        # 2nd call (Climate Risk)
        MagicMock(status_code=200, json=lambda: mock_wb_climate_risk),
        # 3rd call (Comtrade)
        MagicMock(status_code=200, json=lambda: mock_comtrade),
    ]
    mocker.patch("httpx.Client", return_value=mock_http_client)

    # Mock AI Client
    mock_gemini = MagicMock()
    mock_gemini.is_configured.return_value = True
    mock_gemini.generate_text.return_value = mock_ai_result.analysis_text
    mocker.patch("chimera_intel.core.gemini_client.GeminiClient", return_value=mock_gemini)

    # Mock API keys
    mocker.patch("chimera_intel.core.climaint.API_KEYS.comtrade_api_key", "test_key")

    # Run the command
    result = runner.invoke(climaint_app, ["report", "Chile", "Lithium"])

    # Check assertions
    assert result.exit_code == 0
    assert "CLIMAINT Strategic Report: Chile - Lithium" in result.stdout
    assert "This is a mock strategic report" in result.stdout
    assert '"indicator": "Political Stability...' in result.stdout
    assert '"summary_usd": {"Imports": 1500000.0, "Exports": 250000000.0}' in result.stdout
    assert "Synthesizing strategic analysis (AI Core)" in result.stdout


def test_climaint_report_invalid_country():
    """
    Test failure on an invalid country name.
    """
    result = runner.invoke(climaint_app, ["report", "InvalidCountry", "Lithium"])
    assert result.exit_code == 1
    assert "Error: Country 'InvalidCountry' not in mapping." in result.stdout

def test_climaint_report_invalid_resource():
    """
    Test failure on an invalid resource name.
    """
    result = runner.invoke(climaint_app, ["report", "Chile", "InvalidResource"])
    assert result.exit_code == 1
    assert "Error: Resource 'InvalidResource' not in mapping." in result.stdout

def test_climaint_report_ai_failure(mocker, mock_wb_stability, mock_wb_climate_risk, mock_comtrade):
    """
    Test failure when the AI analysis step fails.
    """
    # Mock httpx.Client
    mock_http_client = MagicMock()
    mock_http_client.get.side_effect = [
        MagicMock(status_code=200, json=lambda: mock_wb_stability),
        MagicMock(status_code=200, json=lambda: mock_wb_climate_risk),
        MagicMock(status_code=200, json=lambda: mock_comtrade),
    ]
    mocker.patch("httpx.Client", return_value=mock_http_client)

    # Mock AI Client to be unconfigured
    mock_gemini = MagicMock()
    mock_gemini.is_configured.return_value = False
    mocker.patch("chimera_intel.core.gemini_client.GeminiClient", return_value=mock_gemini)
    
    mocker.patch("chimera_intel.core.climaint.API_KEYS.comtrade_api_key", "test_key")

    result = runner.invoke(climaint_app, ["report", "Chile", "Lithium"])

    assert result.exit_code == 1
    assert "AI Analysis Failed" in result.stdout
    assert "AI Core (Gemini) is not configured" in result.stdout