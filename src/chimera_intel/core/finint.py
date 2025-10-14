import logging
import httpx
from .schemas import FinancialInstrument, InsiderTransaction
from typing import List, Optional
from .config_loader import API_KEYS
import typer
from rich.console import Console
from rich.table import Table
from .project_manager import resolve_target

# --- Logger Configuration ---

logger = logging.getLogger(__name__)

# --- Core Logic ---


async def get_insider_transactions(ticker: str) -> List[InsiderTransaction]:
    """
    Fetches the latest insider transactions for a given stock ticker from the Finnhub API.

    Args:
        ticker: The stock ticker symbol (e.g., 'AAPL').

    Returns:
        A list of InsiderTransaction objects, or an empty list if an error occurs.
    """
    api_key = API_KEYS.finnhub_api_key
    if not api_key:
        logger.error("Finnhub API key is not configured.")
        return []
    url = f"https://finnhub.io/api/v1/stock/insider-transactions?symbol={ticker}&token={api_key}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json().get("data", [])

            return [InsiderTransaction(**item) for item in data]
    except httpx.RequestError as e:
        logger.error(
            f"HTTP request failed while fetching insider transactions for {ticker}: {e}"
        )
        return []
    except Exception as e:
        logger.error(
            f"An unexpected error occurred while fetching insider transactions for {ticker}: {e}"
        )
        return []


# --- CLI Integration ---


app = typer.Typer(
    name="finint",
    help="Financial Intelligence (FININT) Module for tracking market activities.",
    no_args_is_help=True,
)


@app.command("insider-tracking")
def run_insider_tracking(
    target: Optional[str] = typer.Argument(
        None, help="The stock ticker symbol to track (e.g., 'AAPL')."
    ),
    project: Optional[str] = typer.Option(
        None, "--project", "-p", help="The project name to use for context."
    ),
):
    """
    Tracks the latest insider trading activities for a given company.
    """
    console = Console()

    # Resolve the target ticker using the project manager

    ticker = resolve_target(target, project, required_assets=["ticker"])
    if not ticker:
        console.print(
            "[bold red]Error: No target ticker specified or found in the project.[/]"
        )
        raise typer.Exit(code=1)
    console.print(f"[bold green]Fetching insider transactions for {ticker}...[/]")

    # Asynchronously fetch the transactions

    import asyncio

    transactions = asyncio.run(get_insider_transactions(ticker))

    if not transactions:
        console.print("[yellow]No insider transactions found or an error occurred.[/]")
        return
    # Create and display a table of the results

    table = Table(title=f"Insider Transactions for {ticker}")
    table.add_column("Name", style="cyan")
    table.add_column("Share", style="magenta")
    table.add_column("Change", style="green")
    table.add_column("Transaction Date", style="yellow")
    table.add_column("Transaction Price", style="blue")
    table.add_column("Transaction Code", style="red")

    for t in transactions:
        table.add_row(
            t.name,
            str(t.share),
            str(t.change),
            t.transactionDate,
            str(t.transactionPrice),
            t.transactionCode,
        )
    console.print(table)


if __name__ == "__main__":
    app()
