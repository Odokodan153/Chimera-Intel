"""
Module for Blockchain & Cryptocurrency OSINT.

This module provides tools to analyze cryptocurrency wallets on public
blockchains like Ethereum, retrieving balance, transaction history, and more.
"""

import typer
import logging
from typing import Optional, Dict, Union
from datetime import datetime
from .schemas import WalletAnalysisResult, WalletTransaction
from .config_loader import API_KEYS
from .http_client import sync_client
from .utils import save_or_print_results
from .database import save_scan_to_db

logger = logging.getLogger(__name__)


def get_wallet_analysis(address: str) -> WalletAnalysisResult:
    """
    Analyzes an Ethereum wallet to get its balance and recent transactions via Etherscan API.

    Args:
        address (str): The Ethereum wallet address to analyze.

    Returns:
        WalletAnalysisResult: A Pydantic model with the wallet's details.
    """
    api_key = API_KEYS.etherscan_api_key
    if not api_key:
        return WalletAnalysisResult(
            address=address,
            balance_eth="0",
            total_transactions=0,
            error="Etherscan API key not found in .env file.",
        )
    logger.info(f"Analyzing Ethereum wallet: {address}")
    base_url = "https://api.etherscan.io/api"

    try:
        # --- 1. Get ETH Balance ---

        balance_params: Dict[str, Union[str, int]] = {
            "module": "account",
            "action": "balance",
            "address": address,
            "tag": "latest",
            "apikey": api_key,
        }
        balance_response = sync_client.get(base_url, params=balance_params)
        balance_response.raise_for_status()
        balance_data = balance_response.json()

        balance_in_wei = int(balance_data.get("result", 0))
        balance_in_eth = balance_in_wei / 1e18

        # --- 2. Get Transactions ---

        tx_params: Dict[str, Union[str, int]] = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "page": 1,
            "offset": 10,
            "sort": "desc",
            "apikey": api_key,
        }
        tx_response = sync_client.get(base_url, params=tx_params)
        tx_response.raise_for_status()
        tx_data = tx_response.json()

        transactions = []
        for tx in tx_data.get("result", []):
            # Use model_validate with a dictionary to handle the 'from' alias correctly

            tx_dict = {
                "hash": tx.get("hash"),
                "from": tx.get("from"),
                "to": tx.get("to"),
                "value_eth": str(int(tx.get("value", 0)) / 1e18),
                "timestamp": str(datetime.fromtimestamp(int(tx.get("timeStamp", "0")))),
            }
            transactions.append(WalletTransaction.model_validate(tx_dict))
        return WalletAnalysisResult(
            address=address,
            balance_eth=f"{balance_in_eth:.4f}",
            total_transactions=len(transactions),
            recent_transactions=transactions,
        )
    except Exception as e:
        logger.error(f"Failed to analyze wallet {address}: {e}")
        return WalletAnalysisResult(
            address=address,
            balance_eth="0",
            total_transactions=0,
            error=f"An API error occurred: {e}",
        )


# --- Typer CLI Application ---


blockchain_app = typer.Typer()


@blockchain_app.command("analyze")
def run_wallet_analysis(
    address: str = typer.Argument(..., help="The Ethereum wallet address to analyze."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes an Ethereum wallet for balance and recent transactions."""
    results_model = get_wallet_analysis(address)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=address, module="blockchain_wallet", data=results_dict)
