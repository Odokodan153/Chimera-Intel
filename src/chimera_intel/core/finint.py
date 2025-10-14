"""
Module for Financial Intelligence (FININT).

Provides tools to analyze financial data, track insider trading, and assess
the financial health and risks of a company.
"""

import typer
import logging
from typing import Optional
from rich.console import Console
from rich.table import Table

from .schemas import InsiderTradingResult, InsiderTransaction
from .utils import save_or_print_results
from .database import save_scan_to_db
from .config_loader import API_KEYS
from .http_client import sync_client
from .project_manager import resolve_target

logger = logging.getLogger(__name__)
console = Console()


def get_insider_transactions(stock_symbol: str) -> InsiderTradingResult:
    """
    Retrieves insider trading transactions for a given stock symbol using the Finnhub API.
    """
    api_key = API_KEYS.finnhub_api_key
    if not api_key:
        return InsiderTradingResult(
            stock_symbol=stock_symbol,
            error="Finnhub API key not found in .env file.",
        )
    logger.info(f"Fetching insider trading data for symbol: {stock_symbol}")

    base_url = "https://finnhub.io/api/v1/stock/insider-transactions"
    params = {"symbol": stock_symbol, "token": api_key}

    try:
        response = sync_client.get(base_url, params=params)
        response.raise_for_status()
        data = response.json()

        transactions = [
            InsiderTransaction.model_validate(t) for t in data.get("data", [])
        ]
        return InsiderTradingResult(
            stock_symbol=stock_symbol, transactions=transactions
        )
    except Exception as e:
        logger.error(f"Failed to get insider transactions for {stock_symbol}: {e}")
        return InsiderTradingResult(
            stock_symbol=stock_symbol, error=f"An API error occurred: {e}"
        )


# --- Typer CLI Application ---


finint_app = typer.Typer(name="finint", help="Financial Intelligence (FININT) tools.")


@finint_app.command("track-insiders")
def run_insider_tracking(
    stock_symbol: Optional[str] = typer.Option(
        None, "--stock-symbol", "-s", help="The company stock symbol (e.g., AAPL)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Tracks insider trading activity for a given company stock symbol.
    """
    target_symbol = resolve_target(stock_symbol, required_assets=["stock_symbol"])
    console.print(
        f"Tracking insider trading for stock symbol: [bold cyan]{target_symbol}[/bold cyan]"
    )

    results_model = get_insider_transactions(target_symbol)
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)
    if not results_model.transactions:
        console.print("[yellow]No insider trading data found for this symbol.[/yellow]")
        return
    # Display results in a table

    table = Table(
        title=f"Insider Trading Activity for {results_model.stock_symbol}",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Insider Name", style="dim")
    table.add_column("Shares")
    table.add_column("Change")
    table.add_column("Transaction Date")
    table.add_column("Price")
    table.add_column("Code")

    for trans in results_model.transactions:
        table.add_row(
            trans.insiderName,
            str(trans.transactionShares),
            str(trans.change),
            str(trans.transactionDate),
            f"{trans.price:.2f}",
            trans.transactionCode,
        )
    console.print(table)

    # Save results if requested

    results_dict = results_model.model_dump(exclude_none=True)
    if output_file:
        save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_symbol, module="finint_insider_tracking", data=results_dict
    )
