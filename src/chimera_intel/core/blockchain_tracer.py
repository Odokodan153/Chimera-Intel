"""
Cryptocurrency Transaction Tracer Module.

Fetches transaction data for crypto addresses and visualizes
the flow of funds. Uses the Blockchair API.
"""
import typer
import logging
import httpx
import os
from typing import Dict, Any, Optional, List
from .utils import console, save_or_print_results
from .config_loader import API_KEYS
from .http_client import get_async_http_client
from pyvis.network import Network # Re-use the existing 2D grapher tech

logger = logging.getLogger(__name__)
tracer_app = typer.Typer()

BASE_URL = "https://api.blockchair.com"

async def get_address_transactions(
    address: str, chain: str = "bitcoin"
) -> Optional[Dict[str, Any]]:
    """
    Fetches transaction data for a given address from Blockchair.
    
    Note: Free Blockchair API is rate-limited and may not show
    full transaction details.
    """
    api_key = API_KEYS.blockchair_api_key # Get from .env
    url = f"{BASE_URL}/{chain}/dashboards/address/{address}"
    params = {"transaction_details": "true", "limit": 10} # Get last 10 txs
    
    if api_key:
        params["key"] = api_key

    async with get_async_http_client() as client:
        try:
            logger.info(f"Fetching transactions for {address} on {chain}")
            response = await client.get(url, params=params, timeout=30.0)
            response.raise_for_status()
            data = response.json()
            
            if not data.get("data", {}).get(address):
                logger.warning(f"No data found for address {address}")
                return None
            
            return data["data"][address]
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Blockchair API error: {e.response.text}")
            console.print(f"[bold red]API Error:[/bold red] {e.response.json().get('context', {}).get('error')}")
            return None
        except Exception as e:
            logger.error(f"Failed to fetch crypto data: {e}", exc_info=True)
            return None

def generate_transaction_graph(
    address_data: Dict[str, Any], 
    main_address: str, 
    output_path: str
) -> bool:
    """
    Generates an interactive Pyvis graph of transaction flows.
    """
    transactions = address_data.get("transactions", [])
    if not transactions:
        console.print("[yellow]No transactions found to graph.[/yellow]")
        return False

    net = Network(
        height="900px",
        width="100%",
        bgcolor="#222222",
        font_color="white",
        directed=True
    )

    # Add the main address as the central node
    net.add_node(main_address, label=main_address, color="#ff4757", size=25, title="Target Address")

    for tx in transactions:
        tx_hash = tx.get("hash")
        time = tx.get("time")
        balance_change_btc = tx.get("balance_change") / 100_000_000 # Convert Satoshi
        
        # Add the transaction node
        net.add_node(
            tx_hash, 
            label=f"{tx_hash[:10]}...", 
            color="#feca57", 
            shape="square", 
            size=15,
            title=f"Time: {time}\nChange: {balance_change_btc:.8f} BTC"
        )
        
        # This is a simplified view. Blockchair's free API doesn't
        # easily provide the *other* addresses in the tx.
        # A paid API would give inputs and outputs.
        # We will simulate by linking to a generic "External" node.
        
        if balance_change_btc > 0:
            # Money IN
            source_node = f"external_source_{tx_hash[:6]}"
            net.add_node(source_node, label="External Source", color="#1e90ff", shape="dot", size=10)
            net.add_edge(source_node, tx_hash, title=f"{balance_change_btc:.8f} BTC", value=abs(balance_change_btc))
            net.add_edge(tx_hash, main_address)
        else:
            # Money OUT
            dest_node = f"external_dest_{tx_hash[:6]}"
            net.add_node(dest_node, label="External Destination", color="#576574", shape="dot", size=10)
            net.add_edge(tx_hash, dest_node, title=f"{balance_change_btc:.8f} BTC", value=abs(balance_change_btc))
            net.add_edge(main_address, tx_hash)

    net.save_graph(output_path)
    return True


@tracer_app.command("trace")
async def run_crypto_trace(
    address: str = typer.Argument(..., help="The cryptocurrency address to trace."),
    chain: str = typer.Option("bitcoin", "--chain", "-c", help="The blockchain (e.g., bitcoin, ethereum)."),
    output_graph: str = typer.Option(
        None, "--output", "-o", help="Save transaction graph to an HTML file."
    ),
):
    """
    (NEW) Traces transactions for a crypto address and builds a visual dashboard.
    """
    with console.status(f"[bold cyan]Tracing {address} on {chain}...[/bold cyan]"):
        address_data = await get_address_transactions(address, chain)
        
    if not address_data:
        console.print("[bold red]Failed to retrieve transaction data.[/bold red]")
        raise typer.Exit(code=1)
        
    # Print the raw data summary
    summary = {
        "address": address_data.get("address", {}).get("string"),
        "balance_usd": address_data.get("address", {}).get("balance_usd"),
        "received_usd": address_data.get("address", {}).get("received_usd"),
        "spent_usd": address_data.get("address", {}).get("spent_usd"),
        "tx_count": address_data.get("address", {}).get("transaction_count"),
    }
    save_or_print_results(summary, None) # Always print summary

    if output_graph:
        with console.status(f"[bold cyan]Generating graph {output_graph}...[/bold cyan]"):
            success = generate_transaction_graph(address_data, address, output_graph)
            if success:
                console.print(f"[green]Transaction graph saved to {output_graph}[/green]")
            else:
                console.print("[yellow]Could not generate transaction graph.[/yellow]")