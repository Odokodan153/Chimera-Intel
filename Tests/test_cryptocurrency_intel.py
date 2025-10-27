import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import httpx
from typer.testing import CliRunner

from chimera_intel.core.cryptocurrency_intel import (
    get_crypto_data,
    get_crypto_forecast,
    app as crypto_app,  # Import the Typer app
)
from chimera_intel.core.schemas import CryptoData, CryptoForecast


@pytest.fixture
def runner():
    """Provides a Typer CliRunner instance."""
    return CliRunner()


# --- Mock Data ---

@pytest.fixture
def mock_history_data():
    """Mock historical data for successful testing."""
    return {
        "2025-01-01": {"4a. close (USD)": "50000.0"},
        "2025-01-02": {"4a. close (USD)": "51000.0"},
        "2025-01-03": {"4a. close (USD)": "52000.0"},
        "2025-01-04": {"4a. close (USD)": "53000.0"},
        "2025-01-05": {"4a. close (USD)": "54000.0"},
        "2025-01-06": {"4a. close (USD)": "55000.0"},
    }

@pytest.fixture
def mock_successful_crypto_data(mock_history_data):
    """Provides a successful CryptoData object."""
    return CryptoData(symbol="BTC", market="USD", history=mock_history_data)


# --- Tests for get_crypto_data ---

@pytest.mark.asyncio
@patch("chimera_intel.core.cryptocurrency_intel.API_KEYS")
@patch("chimera_intel.core.cryptocurrency_intel.httpx.AsyncClient.get", new_callable=AsyncMock)
async def test_get_crypto_data_success(mock_get, mock_api_keys, mock_history_data):
    """Tests a successful crypto data fetch."""
    # Arrange
    mock_api_keys.alpha_vantage_api_key = "fake_key"
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "Time Series (Digital Currency Daily)": mock_history_data
    }
    mock_get.return_value = mock_response

    # Act
    result = await get_crypto_data("BTC", "USD")

    # Assert
    assert result.history == mock_history_data
    assert result.error is None
    mock_get.assert_called_once()


@pytest.mark.asyncio
@patch("chimera_intel.core.cryptocurrency_intel.API_KEYS")
async def test_get_crypto_data_no_api_key(mock_api_keys):
    """Tests the case where the Alpha Vantage API key is missing."""
    # Arrange
    mock_api_keys.alpha_vantage_api_key = None

    # Act
    result = await get_crypto_data("BTC", "USD")

    # Assert
    assert result.history is None
    assert result.error == "Alpha Vantage API key not configured."


@pytest.mark.asyncio
@patch("chimera_intel.core.cryptocurrency_intel.API_KEYS")
@patch("chimera_intel.core.cryptocurrency_intel.httpx.AsyncClient.get", new_callable=AsyncMock)
async def test_get_crypto_data_api_error_response(mock_get, mock_api_keys):
    """Tests the case where the API returns an error message (no time series)."""
    # Arrange
    mock_api_keys.alpha_vantage_api_key = "fake_key"
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"Error Message": "Invalid symbol."}
    mock_get.return_value = mock_response

    # Act
    result = await get_crypto_data("INVALID", "USD")

    # Assert
    assert result.history is None
    assert "Could not retrieve historical data" in result.error


@pytest.mark.asyncio
@patch("chimera_intel.core.cryptocurrency_intel.API_KEYS")
@patch("chimera_intel.core.cryptocurrency_intel.httpx.AsyncClient.get", new_callable=AsyncMock)
async def test_get_crypto_data_http_exception(mock_get, mock_api_keys):
    """Tests the case where httpx.get raises an exception."""
    # Arrange
    mock_api_keys.alpha_vantage_api_key = "fake_key"
    mock_get.side_effect = httpx.RequestError("Network connection failed")

    # Act
    result = await get_crypto_data("BTC", "USD")

    # Assert
    assert result.history is None
    assert "Network connection failed" in result.error


# --- Tests for get_crypto_forecast ---

def test_get_crypto_forecast_success(mock_successful_crypto_data):
    """Tests a successful crypto forecast."""
    # Act
    result = get_crypto_forecast(mock_successful_crypto_data, 7)

    # Assert
    assert result.forecast is not None
    assert len(result.forecast) == 7
    assert result.error is None
    # Check that prices are plausible (simple linear trend)
    assert result.forecast[0] > 55000.0


def test_get_crypto_forecast_with_data_error(mock_successful_crypto_data):
    """Tests forecasting when the input CryptoData has an error."""
    # Arrange
    error_data = CryptoData(symbol="BTC", market="USD", error="Test Error")

    # Act
    result = get_crypto_forecast(error_data, 7)

    # Assert
    assert result.forecast is None
    assert result.error == "Test Error"


def test_get_crypto_forecast_with_no_history():
    """Tests forecasting when the input CryptoData has no history."""
    # Arrange
    no_history_data = CryptoData(symbol="BTC", market="USD", history=None)

    # Act
    result = get_crypto_forecast(no_history_data, 7)

    # Assert
    assert result.forecast is None
    assert "No historical data available" in result.error


@patch("chimera_intel.core.cryptocurrency_intel.ARIMA")
def test_get_crypto_forecast_arima_exception(mock_arima, mock_successful_crypto_data):
    """Tests the exception handler for the ARIMA model."""
    # Arrange
    mock_model_fit = MagicMock()
    mock_model_fit.forecast.side_effect = Exception("ARIMA fitting failed")
    mock_model = MagicMock()
    mock_model.fit.return_value = mock_model_fit
    mock_arima.return_value = mock_model
    
    # Act
    result = get_crypto_forecast(mock_successful_crypto_data, 7)

    # Assert
    assert result.forecast is None
    assert "ARIMA fitting failed" in result.error


# --- Tests for run_crypto_forecast (Typer CLI) ---

@patch("chimera_intel.core.cryptocurrency_intel.get_crypto_forecast")
@patch("asyncio.run")
def test_cli_forecast_success(mock_asyncio_run, mock_get_forecast, runner, mock_successful_crypto_data):
    """Tests the full CLI command happy path."""
    # Arrange
    mock_asyncio_run.return_value = mock_successful_crypto_data
    mock_forecast = CryptoForecast(symbol="BTC", forecast=[60000.12, 61000.34])
    mock_get_forecast.return_value = mock_forecast
    
    # Act
    # FIX: Pass 'BTC' as an option --symbol 'BTC'
    result = runner.invoke(crypto_app, ["forecast", "--symbol", "BTC", "--days", "2"])

    # Assert
    assert result.exit_code == 0
    mock_asyncio_run.assert_called_once()
    mock_get_forecast.assert_called_with(mock_successful_crypto_data, 2)
    assert "2-Day Price Forecast for BTC" in result.stdout
    assert "Day 1" in result.stdout
    assert "$60,000.12" in result.stdout
    assert "Day 2" in result.stdout
    assert "$61,000.34" in result.stdout
    assert "Error:" not in result.stdout


@patch("chimera_intel.core.cryptocurrency_intel.get_crypto_forecast")
@patch("asyncio.run")
def test_cli_forecast_data_fetch_error(mock_asyncio_run, mock_get_forecast, runner):
    """Tests the CLI command when get_crypto_data returns an error."""
    # Arrange
    error_data = CryptoData(symbol="BTC", market="USD", error="API key invalid")
    mock_asyncio_run.return_value = error_data
    
    # We also mock get_crypto_forecast to show it returns an error
    mock_forecast = CryptoForecast(symbol="BTC", error="API key invalid")
    mock_get_forecast.return_value = mock_forecast

    # Act
    # FIX: Pass 'BTC' as an option --symbol 'BTC'
    result = runner.invoke(crypto_app, ["forecast", "--symbol", "BTC"])

    # Assert
    assert result.exit_code == 0 # CLI command handles the error gracefully
    mock_asyncio_run.assert_called_once()
    mock_get_forecast.assert_called_with(error_data, 7) # 7 is the default
    assert "[bold red]Error:[/] API key invalid" in result.stdout
    assert "Forecast" not in result.stdout # No table printed


@patch("chimera_intel.core.cryptocurrency_intel.get_crypto_forecast")
@patch("asyncio.run")
def test_cli_forecast_model_error(mock_asyncio_run, mock_get_forecast, runner, mock_successful_crypto_data):
    """Tests the CLI command when get_crypto_forecast returns an error."""
    # Arrange
    mock_asyncio_run.return_value = mock_successful_crypto_data
    error_forecast = CryptoForecast(symbol="BTC", error="ARIMA failed")
    mock_get_forecast.return_value = error_forecast

    # Act
    # FIX: Pass 'BTC' as an option --symbol 'BTC'
    result = runner.invoke(crypto_app, ["forecast", "--symbol", "BTC"])

    # Assert
    assert result.exit_code == 0
    mock_asyncio_run.assert_called_once()
    mock_get_forecast.assert_called_with(mock_successful_crypto_data, 7)
    assert "[bold red]Error:[/] ARIMA failed" in result.stdout
    assert "Forecast" not in result.stdout


@patch("chimera_intel.core.cryptocurrency_intel.get_crypto_forecast")
@patch("asyncio.run")
def test_cli_forecast_no_forecast_data(mock_asyncio_run, mock_get_forecast, runner, mock_successful_crypto_data):
    """Tests the CLI check for when forecast is None (mypy fix)."""
    # Arrange
    mock_asyncio_run.return_value = mock_successful_crypto_data
    # Simulate a successful return but with no forecast list
    no_forecast = CryptoForecast(symbol="BTC", forecast=None, error=None)
    mock_get_forecast.return_value = no_forecast

    # Act
    # FIX: Pass 'BTC' as an option --symbol 'BTC'
    result = runner.invoke(crypto_app, ["forecast", "--symbol", "BTC"])

    # Assert
    assert result.exit_code == 0
    assert "[bold red]Error:[/] Forecast generation failed to produce data." in result.stdout
    assert "Forecast" not in result.stdout