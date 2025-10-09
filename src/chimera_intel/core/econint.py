import logging
import asyncio
from .schemas import MacroIndicators, MicroIndicators
import httpx
import wbdata
import typer
from rich.console import Console
from rich.table import Table
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)


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

        # Explicitly retrieving values and casting to float (or None) to satisfy mypy

        gdp_val = latest_values.get("NY.GDP.MKTP.CD")
        inflation_val = latest_values.get("FP.CPI.TOTL.ZG")
        unemployment_val = latest_values.get("SL.UEM.TOTL.ZS")

        return MacroIndicators(
            country=country_name,
            gdp_latest=float(gdp_val) if gdp_val is not None else None,
            inflation_latest=(
                float(inflation_val) if inflation_val is not None else None
            ),
            unemployment_latest=(
                float(unemployment_val) if unemployment_val is not None else None
            ),
        )
    except Exception as e:
        logger.error(f"Failed to fetch World Bank data for {country_code}: {e}")
        # Explicitly setting optional fields to None in the error case to satisfy mypy

        return MacroIndicators(
            country=country_code,
            error=str(e),
            gdp_latest=None,
            inflation_latest=None,
            unemployment_latest=None,
        )


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
            symbol=symbol,
            error="Alpha Vantage API key is not configured.",
            latest_price=None,  # Explicitly setting optional fields to None
            market_cap=None,
            pe_ratio=None,
        )
    url = f"https://www.alphavantage.co/query?function=OVERVIEW&symbol={symbol}&apikey={api_key}"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

            # Helper function to correctly handle AlphaVantage's "None" string or missing keys

            def clean_value(val):
                return val if val and val != "None" else None

            if "Note" in data or not data or data.get("Symbol") is None:
                error_msg = data.get("Note", "Invalid symbol or no data received.")
                return MicroIndicators(
                    symbol=symbol,
                    error=error_msg,
                    latest_price=None,  # Explicitly setting optional fields to None
                    market_cap=None,
                    pe_ratio=None,
                )
            # Safely retrieve and clean string values

            last_price = clean_value(data.get("LastPrice"))
            market_cap_val = clean_value(data.get("MarketCapitalization"))
            pe_ratio = clean_value(data.get("PERatio"))

            return MicroIndicators(
                symbol=data.get("Symbol"),
                # Convert to float if a valid value is present, otherwise use None.
                latest_price=float(last_price) if last_price else None,
                market_cap=market_cap_val,
                pe_ratio=float(pe_ratio) if pe_ratio else None,
            )
        except Exception as e:
            logger.error(f"Failed to fetch Alpha Vantage data for {symbol}: {e}")
            # Explicitly setting optional fields to None in the error case to satisfy mypy

            return MicroIndicators(
                symbol=symbol,
                error=str(e),
                latest_price=None,
                market_cap=None,
                pe_ratio=None,
            )


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
