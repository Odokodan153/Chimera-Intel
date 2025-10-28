import logging
import asyncio
from .schemas import CryptoData, CryptoForecast
import httpx
import pandas as pd
from statsmodels.tsa.arima.model import ARIMA
import typer
from rich.console import Console
from rich.table import Table
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)


async def get_crypto_data(symbol: str, market: str) -> CryptoData:
    """
    Fetches daily historical data for a cryptocurrency from Alpha Vantage.

    Args:
        symbol (str): The cryptocurrency symbol (e.g., 'BTC').
        market (str): The market symbol (e.g., 'USD').

    Returns:
        CryptoData: The historical data.
    """
    api_key = API_KEYS.alpha_vantage_api_key
    if not api_key:
        return CryptoData(
            symbol=symbol, market=market, error="Alpha Vantage API key not configured."
        )
    url = f"https://www.alphavantage.co/query?function=DIGITAL_CURRENCY_DAILY&symbol={symbol}&market={market}&apikey={api_key}"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

            if "Time Series (Digital Currency Daily)" not in data:
                return CryptoData(
                    symbol=symbol,
                    market=market,
                    error="Could not retrieve historical data. Check the symbol and market.",
                )
            return CryptoData(
                symbol=symbol,
                market=market,
                history=data["Time Series (Digital Currency Daily)"],
            )
        except Exception as e:
            logger.error(f"Failed to fetch Alpha Vantage crypto data for {symbol}: {e}")
            return CryptoData(symbol=symbol, market=market, error=str(e))


def get_crypto_forecast(data: CryptoData, days: int) -> CryptoForecast:
    """
    Generates a price forecast for a cryptocurrency using an ARIMA model.

    Args:
        data (CryptoData): The historical cryptocurrency data.
        days (int): The number of days to forecast.

    Returns:
        CryptoForecast: The price forecast.
    """
    if data.error or not data.history:
        return CryptoForecast(
            symbol=data.symbol,
            error=data.error or "No historical data available for forecasting.",
        )
    try:
        df = pd.DataFrame.from_dict(data.history, orient="index", dtype=float)
        df.index = pd.to_datetime(df.index)
        closing_prices = df[f"4a. close ({data.market})"].sort_index()

        # A simple ARIMA model

        model = ARIMA(closing_prices, order=(5, 1, 0))
        model_fit = model.fit()
        forecast = model_fit.forecast(steps=days)

        return CryptoForecast(symbol=data.symbol, forecast=forecast.tolist())
    except Exception as e:
        logger.error(f"Forecasting failed for {data.symbol}: {e}")
        return CryptoForecast(symbol=data.symbol, error=str(e))


app = typer.Typer(
    name="crypto",
    help="Provides cryptocurrency market intelligence and forecasting.",
    no_args_is_help=True,
)


@app.command("forecast")
def run_crypto_forecast(
    # FIX: Change from typer.Argument to a required typer.Option to fix CLI parsing issue
    symbol: str = typer.Option(
        ..., "--symbol", "-s", help="The cryptocurrency symbol (e.g., 'BTC')."
    ),
    market: str = typer.Option(
        "USD", "--market", "-m", help="The market to compare against."
    ),
    days: int = typer.Option(7, "--days", "-d", help="The number of days to forecast."),
):
    """Forecasts the price of a cryptocurrency."""
    console = Console()

    async def get_data():
        return await get_crypto_data(symbol, market)

    with console.status("[bold green]Fetching cryptocurrency data...[/]"):
        crypto_data = asyncio.run(get_data())
    with console.status("[bold green]Generating forecast...[/]"):
        forecast_result = get_crypto_forecast(crypto_data, days)
        
    if forecast_result.error:
        # FIX: Replace console.print with typer.echo and use plain text for test compatibility.
        # The test assertions will fail due to mismatched formatting tags but this correctly prints the message.
        typer.echo(f"Error: {forecast_result.error}")
        return
        
    # FIX: Explicitly check for the forecast data to satisfy the type checker (mypy).

    if forecast_result.forecast is None:
        # FIX: Replace console.print with typer.echo and use plain text for test compatibility.
        typer.echo("Error: Forecast generation failed to produce data.")
        return
        
    table = Table(title=f"{days}-Day Price Forecast for {symbol}")
    table.add_column("Day", style="cyan")
    table.add_column("Predicted Price (USD)", style="magenta")

    for i, price in enumerate(forecast_result.forecast, 1):
        table.add_row(f"Day {i}", f"${price:,.2f}")
    console.print(table)