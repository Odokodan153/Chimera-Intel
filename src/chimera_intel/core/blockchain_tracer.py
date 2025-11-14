"""
Cryptocurrency Transaction Tracer Module.

Fetches transaction data for crypto addresses and visualizes
the flow of funds. Uses the Blockchair API.
"""
import typer
import logging
import httpx
from typing import Dict, Any, Optional
from .utils import console, save_or_print_results
from .config_loader import API_KEYS
from .http_client import get_async_http_client 
from pyvis.network import Network  

logger = logging.getLogger(__name__)
tracer_app = typer.Typer()

BASE_URL = "https://api.blockchair.com"

async def get_address_transactions(
    address: str, chain: str = "bitcoin"
) -> Optional[Dict[str, Any]]:
    """
    (REAL) Fetches transaction data for a given address from Blockchair.
    
    Note: Free Blockchair API is rate-limited and may not show
    full transaction details.
    """
    api_key = API_KEYS.blockchair_api_key  # Get from .env
    # We need to fetch the full transaction data to get inputs/outputs
    url = f"{BASE_URL}/{chain}/dashboards/address/{address}"
    params = {"transaction_details": "true", "limit": 10}  # Get last 10 txs
    
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
            
            # (REAL) Also fetch the transaction details (inputs/outputs)
            tx_hashes = data["data"][address].get("transactions", [])
            if tx_hashes:
                tx_url = f"{BASE_URL}/{chain}/dashboards/transactions/{','.join(tx_hashes[:10])}" # Limit to 10 hashes for API
                tx_response = await client.get(tx_url, params={"key": api_key} if api_key else {}, timeout=30.0)
                tx_data = tx_response.json()
                
                # Embed the detailed transaction data into the main response
                data["data"][address]["transaction_details"] = tx_data.get("data", {})
                
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
    output_path: str,
    chain: str = "bitcoin"
) -> bool:
    """
    (REAL) Generates an interactive Pyvis graph of real transaction flows.
    """
    transactions = address_data.get("transaction_details", {})
    if not transactions:
        console.print("[yellow]No detailed transactions found to graph.[/yellow]")
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

    unit = "BTC" if chain == "bitcoin" else "ETH"

    for tx_hash, tx in transactions.items():
        tx_details = tx.get("transaction", {})
        time = tx_details.get("time")
        
        # Add the transaction node
        net.add_node(
            tx_hash, 
            label=f"{tx_hash[:10]}...", 
            color="#feca57", 
            shape="square", 
            size=15,
            title=f"Time: {time}\nHash: {tx_hash}"
        )
        
        # (REAL) Process Inputs
        inputs = tx.get("inputs", [])
        for inp in inputs:
            input_addr = inp.get("recipient", "Unknown_Input")
            value = inp.get("value", 0) / (10**8 if chain == "bitcoin" else 10**18) # Convert Satoshi/Wei
            
            # Add the input node
            if not net.get_node(input_addr):
                net.add_node(input_addr, label=input_addr, color="#1e90ff", shape="dot", size=10)
            
            # Draw edge from input address to transaction
            net.add_edge(input_addr, tx_hash, title=f"{value:.8f} {unit}", value=value)
            
        # (REAL) Process Outputs
        outputs = tx.get("outputs", [])
        for outp in outputs:
            output_addr = outp.get("recipient", "Unknown_Output")
            value = outp.get("value", 0) / (10**8 if chain == "bitcoin" else 10**18)
            
            # Add the output node
            if not net.get_node(output_addr):
                net.add_node(output_addr, label=output_addr, color="#576574", shape="dot", size=10)
                
            # Draw edge from transaction to output address
            net.add_edge(tx_hash, output_addr, title=f"{value:.8f} {unit}", value=value)

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
    (REAL) Traces transactions for a crypto address and builds a visual dashboard.
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
            success = generate_transaction_graph(address_data, address, output_graph, chain)
            if success:
                console.print(f"[green]Transaction graph saved to {output_graph}[/green]")
            else:
                console.print("[yellow]Could not generate transaction graph.[/yellow]")