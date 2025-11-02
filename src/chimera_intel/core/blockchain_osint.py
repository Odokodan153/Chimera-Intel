"""
Module for Blockchain & Cryptocurrency OSINT.

This module provides tools to analyze cryptocurrency wallets on public
blockchains like Ethereum, retrieving balance, transaction history, and more.
"""

import typer
import logging
from typing import Optional, Dict, Union
from datetime import datetime
from chimera_intel.core.schemas import SmartContractAnalysis, TokenFlow, TokenFlowResult
from .schemas import WalletAnalysisResult, WalletTransaction
from .config_loader import API_KEYS
from .http_client import sync_client
from .utils import save_or_print_results, console
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

        # --- FIX START: Add check for status and result key ---
        if balance_data.get("status") != "1" or "result" not in balance_data:
            raise KeyError(
                f"API response error or malformed data: {balance_data.get('message', 'No message')}"
            )
        # --- FIX END ---

        balance_in_wei = int(balance_data.get("result", 0))  # or balance_data["result"]
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

        # --- FIX START: Add check for status and result key ---
        if tx_data.get("status") != "1" or "result" not in tx_data:
            raise KeyError(
                f"API response error or malformed data for txlist: {tx_data.get('message', 'No message')}"
            )
        # --- FIX END ---

        transactions = []
        # Use .get() for safety in case tx_data["result"] is not a list
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


def analyze_smart_contract(address: str) -> SmartContractAnalysis:
    """
    Analyzes an Ethereum smart contract for verification status, creator, and token info.
    """
    api_key = API_KEYS.etherscan_api_key
    if not api_key:
        return SmartContractAnalysis(address=address, error="Etherscan API key not found.")

    logger.info(f"Analyzing smart contract: {address}")
    base_url = "https://api.etherscan.io/api"
    
    try:
        # 1. Get Contract Source Code and Verification Status
        contract_params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key,
        }
        response = sync_client.get(base_url, params=contract_params)
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "1" or not isinstance(data.get("result"), list) or len(data["result"]) == 0:
            return SmartContractAnalysis(address=address, error=f"API Error: {data.get('message', 'No result')}")
        
        contract_info = data["result"][0]
        source_code = contract_info.get("SourceCode", "")
        
        analysis = SmartContractAnalysis(
            address=address,
            is_verified=bool(source_code), # True if SourceCode is not empty
            contract_name=contract_info.get("ContractName"),
            token_name=contract_info.get("TokenName") or None, # Etherscan uses "" for N/A
            token_symbol=contract_info.get("TokenSymbol") or None,
            source_code_snippet=f"{source_code[:150]}..." if source_code else "Not verified."
        )

        # 2. Get Contract Creator (if verified, sometimes included)
        # A more robust way is to use "getcontractcreation"
        try:
            creator_params = {
                "module": "contract",
                "action": "getcontractcreation",
                "contractaddresses": address,
                "apikey": api_key,
            }
            creator_response = sync_client.get(base_url, params=creator_params)
            creator_response.raise_for_status()
            creator_data = creator_response.json()
            
            if creator_data.get("status") == "1" and isinstance(creator_data.get("result"), list) and len(creator_data["result"]) > 0:
                analysis.creator_address = creator_data["result"][0].get("contractCreator")
                analysis.creator_tx_hash = creator_data["result"][0].get("txHash")

        except Exception as e:
            logger.warning(f"Could not fetch contract creator info for {address}: {e}")

        return analysis

    except Exception as e:
        logger.error(f"Failed to analyze contract {address}: {e}")
        return SmartContractAnalysis(address=address, error=f"An API error occurred: {e}")


def track_token_flow(address: str, token_symbol: Optional[str] = None) -> TokenFlowResult:
    """
    Tracks recent ERC20 token flows (max 50) for a specific wallet.
    Optionally filters by token_symbol.
    """
    api_key = API_KEYS.etherscan_api_key
    if not api_key:
        return TokenFlowResult(address=address, error="Etherscan API key not found.")

    logger.info(f"Tracking token flow for wallet: {address}")
    base_url = "https://api.etherscan.io/api"
    
    try:
        tx_params = {
            "module": "account",
            "action": "tokentx",
            "address": address,
            "page": 1,
            "offset": 50, # Get recent 50 token transfers
            "sort": "desc",
            "apikey": api_key,
        }
        
        response = sync_client.get(base_url, params=tx_params)
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "1":
            # Status "0" is common for no transactions, which is not an error
            if data.get("message") == "No transactions found":
                return TokenFlowResult(address=address, total_flows_tracked=0)
            raise KeyError(f"API response error: {data.get('message', 'No message')}")
        
        result_list = TokenFlowResult(
            address=address, 
            token_symbol_filter=token_symbol
        )
        
        api_results = data.get("result", [])
        if not isinstance(api_results, list):
             return TokenFlowResult(address=address, error="API returned malformed result (not a list)")

        for tx in api_results:
            tx_token_symbol = tx.get("tokenSymbol")
            
            # Apply filter if provided
            if token_symbol and tx_token_symbol and tx_token_symbol.lower() != token_symbol.lower():
                continue
            
            try:
                # Calculate amount using token's decimals
                decimals = int(tx.get("tokenDecimal", "18"))
                amount = int(tx.get("value", "0")) / (10 ** decimals)
                
                flow = TokenFlow(
                    hash=tx.get("hash"),
                    from_address=tx.get("from"),
                    to_address=tx.get("to"),
                    token_symbol=tx_token_symbol,
                    amount=amount,
                    timestamp=str(datetime.fromtimestamp(int(tx.get("timeStamp", "0")))),
                )
                result_list.token_flows.append(flow)
            except Exception as e:
                logger.warning(f"Could not parse token tx {tx.get('hash')}: {e}")
        
        result_list.total_flows_tracked = len(result_list.token_flows)
        return result_list

    except Exception as e:
        logger.error(f"Failed to track token flow for {address}: {e}")
        return TokenFlowResult(address=address, error=f"An API error occurred: {e}")




# --- Typer CLI Application ---

blockchain_app = typer.Typer(
    name="blockchain",
    help="Blockchain & Cryptocurrency OSINT tools."
)


@blockchain_app.command("analyze")
def run_wallet_analysis(
    address: str = typer.Argument(..., help="The Ethereum wallet address to analyze."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes an Ethereum wallet for balance and recent transactions."""
    console.print(f"[bold cyan]Analyzing wallet:[/bold cyan] {address}")
    results_model = get_wallet_analysis(address)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=address, module="blockchain_wallet", data=results_dict)

@blockchain_app.command("contract")
def run_contract_analysis(
    address: str = typer.Argument(..., help="The smart contract address to analyze."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes a smart contract for verification, creator, and risks."""
    console.print(f"[bold cyan]Analyzing smart contract:[/bold cyan] {address}")
    results_model = analyze_smart_contract(address)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=address, module="blockchain_contract", data=results_dict)

@blockchain_app.command("token-flow")
def run_token_flow(
    address: str = typer.Argument(..., help="The wallet address to track."),
    token: Optional[str] = typer.Option(
        None, "--token", "-t", help="[Optional] Filter by token symbol (e.g., USDT, DAI)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Tracks recent ERC20 token flows (max 50) for a specific wallet."""
    if token:
        console.print(f"[bold cyan]Tracking {token} flow for:[/bold cyan] {address}")
    else:
        console.print(f"[bold cyan]Tracking all token flows for:[/bold cyan] {address}")
        
    results_model = track_token_flow(address, token_symbol=token)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=address, 
        module="blockchain_token_flow", 
        data=results_dict
    )

