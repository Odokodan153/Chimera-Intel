"""
Module for Financial Intelligence (FININT).

Handles the gathering and analysis of financial data that can provide strategic
insights, such as insider trading activity.
"""

import typer
import logging
from typing import Optional
from sec_api import InsiderTradingApi  # type: ignore
from .schemas import InsiderTradingResult, InsiderTransaction
from .utils import save_or_print_results
from .database import save_scan_to_db
from .config_loader import API_KEYS
from .project_manager import resolve_target

logger = logging.getLogger(__name__)


def track_insider_trading(ticker: str) -> InsiderTradingResult:
    """
    Tracks the latest insider trading activities for a given stock ticker.

    Args:
        ticker (str): The stock market ticker symbol (e.g., "AAPL").

    Returns:
        InsiderTradingResult: A Pydantic model with the latest insider transactions.
    """
    api_key = API_KEYS.sec_api_io_key
    if not api_key:
        return InsiderTradingResult(
            ticker=ticker, error="SEC API (sec-api.io) key not found in .env file."
        )
    logger.info(f"Fetching insider trading data for ticker: {ticker}")
    insider_api = InsiderTradingApi(api_key=api_key)

    try:
        # Get the most recent 50 transactions

        transactions_data = insider_api.get_insider_transactions(
            lookup=ticker, page_size=50
        )

        transactions = [
            InsiderTransaction.model_validate(tx)
            for tx in transactions_data["transactions"]
        ]

        return InsiderTradingResult(
            ticker=ticker,
            total_transactions=transactions_data["total"],
            transactions=transactions,
        )
    except Exception as e:
        logger.error(f"Failed to get insider trading data for {ticker}: {e}")
        return InsiderTradingResult(ticker=ticker, error=f"An API error occurred: {e}")


# --- Typer CLI Application ---


finint_app = typer.Typer()


@finint_app.command("insider-tracking")
def run_insider_tracking(
    ticker_symbol: Optional[str] = typer.Argument(
        None, help="The stock ticker to track. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Tracks the latest insider trading activity for a given company."""
    target_ticker = resolve_target(ticker_symbol, required_assets=["ticker"])

    results_model = track_insider_trading(target_ticker)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_ticker, module="finint_insider_tracking", data=results_dict
    )
