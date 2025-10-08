import logging
import asyncio
from typing import Optional
from pydantic import BaseModel, Field
import httpx
import wbdata
import typer
from rich.console import Console
from rich.table import Table
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)


class MacroIndicators(BaseModel):
    """Represents key macroeconomic indicators for a country."""

    country: str
    gdp_latest: Optional[float] = Field(
        None, description="Most recent Gross Domestic Product (in current US$)."
    )
    inflation_latest: Optional[float] = Field(
        None, description="Most recent inflation rate (annual %)."
    )
    unemployment_latest: Optional[float] = Field(
        None, description="Most recent unemployment rate (%)."
    )
    error: Optional[str] = None


class MicroIndicators(BaseModel):
    """Represents key microeconomic indicators for a company."""

    symbol: str
    latest_price: Optional[float] = Field(None, description="Latest stock price.")
    market_cap: Optional[str] = Field(
        None, description="Company's market capitalization."
    )
    pe_ratio: Optional[float] = Field(None, description="Price-to-Earnings ratio.")
    error: Optional[str] = None


def get_macro_indicators(country_code: str) -> MacroIndicators:
    """
    Fetches key macroeconomic indicators for a given country from the World Bank.

    Args:
        country_code (str): The ISO 3166-1 alpha-2 country code (e.g., 'US', 'DE').

    Returns:
        MacroIndicators: The macroeconomic data.
    """
    try:
        country_name = wbdata.get_countries(country_code)[0]["name"]
        indicators = {
            "NY.GDP.MKTP.CD": "gdp_latest",  # GDP
            "FP.CPI.TOTL.ZG": "inflation_latest",  # Inflation
            "SL.UEM.TOTL.ZS": "unemployment_latest",  # Unemployment
        }
        data = wbdata.get_dataframe(
            indicators, country=country_code, most_recent_values=True
        )

        # The data comes back with years as index, we just need the values

        latest_values = data.iloc[-1].to_dict()

        return MacroIndicators(
            country=country_name,
            gdp_latest=latest_values.get("NY.GDP.MKTP.CD"),
            inflation_latest=latest_values.get("FP.CPI.TOTL.ZG"),
            unemployment_latest=latest_values.get("SL.UEM.TOTL.ZS"),
        )
    except Exception as e:
        logger.error(f"Failed to fetch World Bank data for {country_code}: {e}")
        return MacroIndicators(country=country_code, error=str(e))


async def get_micro_indicators(symbol: str) -> MicroIndicators:
    """
    Fetches key stock market indicators for a company from Alpha Vantage.

    Args:
        symbol (str): The stock ticker symbol (e.g., 'AAPL', 'GOOGL').

    Returns:
        MicroIndicators: The company's financial data.
    """
    api_key = API_KEYS.alpha_vantage_api_key
    if not api_key:
        return MicroIndicators(
            symbol=symbol, error="Alpha Vantage API key is not configured."
        )
    url = f"https://www.alphavantage.co/query?function=OVERVIEW&symbol={symbol}&apikey={api_key}"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

            if "Note" in data or not data:  # Handle API rate limiting or invalid symbol
                error_msg = data.get("Note", "Invalid symbol or no data received.")
                return MicroIndicators(symbol=symbol, error=error_msg)
            return MicroIndicators(
                symbol=data.get("Symbol"),
                latest_price=float(data.get("LastPrice", 0.0)),
                market_cap=data.get("MarketCapitalization"),
                pe_ratio=float(data.get("PERatio", 0.0)),
            )
        except Exception as e:
            logger.error(f"Failed to fetch Alpha Vantage data for {symbol}: {e}")
            return MicroIndicators(symbol=symbol, error=str(e))


app = typer.Typer(
    name="economics",
    help="Provides macro and micro economic intelligence.",
    no_args_is_help=True,
)


@app.command("macro")
def run_macro_analysis(
    country_code: str = typer.Argument(
        ..., help="The ISO alpha-2 country code (e.g., 'US', 'DE')."
    )
):
    """Analyzes macroeconomic indicators for a country."""
    console = Console()
    with console.status("[bold green]Fetching macroeconomic data...[/]"):
        result = get_macro_indicators(country_code)
    if result.error:
        console.print(f"[bold red]Error:[/] {result.error}")
        return
    table = Table(title=f"Macroeconomic Indicators for {result.country}")
    table.add_column("Indicator", style="cyan")
    table.add_column("Latest Value", style="magenta")

    table.add_row(
        "GDP (current US$)",
        f"${result.gdp_latest:,.2f}" if result.gdp_latest else "N/A",
    )
    table.add_row(
        "Inflation (annual %)",
        f"{result.inflation_latest:.2f}%" if result.inflation_latest else "N/A",
    )
    table.add_row(
        "Unemployment Rate (%)",
        f"{result.unemployment_latest:.2f}%" if result.unemployment_latest else "N/A",
    )

    console.print(table)


@app.command("micro")
def run_micro_analysis(
    symbol: str = typer.Argument(
        ..., help="The company's stock ticker symbol (e.g., 'AAPL')."
    )
):
    """Analyzes microeconomic indicators for a company."""
    console = Console()

    async def get_data():
        return await get_micro_indicators(symbol)

    with console.status("[bold green]Fetching company financial data...[/]"):
        result = asyncio.run(get_data())
    if result.error:
        console.print(f"[bold red]Error:[/] {result.error}")
        return
    table = Table(title=f"Microeconomic Indicators for {result.symbol}")
    table.add_column("Indicator", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row(
        "Latest Price", f"${result.latest_price:.2f}" if result.latest_price else "N/A"
    )
    table.add_row("Market Cap", result.market_cap if result.market_cap else "N/A")
    table.add_row("P/E Ratio", f"{result.pe_ratio:.2f}" if result.pe_ratio else "N/A")

    console.print(table)
