import logging
import asyncio
from .schemas import ShipmentDetails, TrackingUpdate
import httpx
import typer
from rich.console import Console
from rich.table import Table
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)



async def track_shipment(tracking_code: str, carrier: str) -> ShipmentDetails:
    """
    Tracks a shipment using the EasyPost API.

    Args:
        tracking_code (str): The tracking code of the shipment.
        carrier (str): The carrier of the shipment (e.g., "USPS", "FedEx").

    Returns:
        ShipmentDetails: The tracking details of the shipment.
    """
    api_key = API_KEYS.easypost_api_key
    if not api_key:
        return ShipmentDetails(
            tracking_code=tracking_code,
            carrier=carrier,
            status="Error",
            error="EasyPost API key is not configured.",
        )
    url = "https://api.easypost.com/v2/trackers"
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {
        "tracker": {
            "tracking_code": tracking_code,
            "carrier": carrier,
        }
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

            updates = [
                TrackingUpdate(
                    status=update.get("status"),
                    message=update.get("message"),
                    timestamp=update.get("datetime"),
                )
                for update in data.get("tracking_details", [])
            ]

            return ShipmentDetails(
                tracking_code=data.get("tracking_code"),
                carrier=data.get("carrier"),
                status=data.get("status"),
                estimated_delivery_date=data.get("est_delivery_date"),
                updates=updates,
            )
        except httpx.HTTPStatusError as e:
            logger.error(f"Error tracking shipment {tracking_code}: {e}")
            return ShipmentDetails(
                tracking_code=tracking_code,
                carrier=carrier,
                status="Error",
                error=f"API error: {e.response.text}",
            )
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
            return ShipmentDetails(
                tracking_code=tracking_code,
                carrier=carrier,
                status="Error",
                error=str(e),
            )


app = typer.Typer(
    name="logistics",
    help="Provides logistics and shipment tracking intelligence.",
    no_args_is_help=True,
)


@app.command("track")
def run_shipment_tracking_cli(
    tracking_code: str = typer.Argument(..., help="The shipment's tracking code."),
    carrier: str = typer.Option(
        ..., "--carrier", "-c", help="The carrier (e.g., USPS, FedEx)."
    ),
):
    """
    Tracks a shipment and displays its current status and history.
    """
    console = Console()

    async def track():
        return await track_shipment(tracking_code, carrier)

    with console.status("[bold green]Tracking shipment...[/]"):
        result = asyncio.run(track())
        
    if result.error:
        # FIX: Use typer.echo and raise typer.Exit(code=1) to ensure a non-zero exit code on failure for testing.
        typer.echo(f"Error: {result.error}", err=True)
        raise typer.Exit(code=1)
        
    console.print(
        f"[bold]Status for {result.tracking_code} ({result.carrier}):[/] {result.status}"
    )
    if result.estimated_delivery_date:
        console.print(
            f"[bold]Estimated Delivery:[/bold] {result.estimated_delivery_date}"
        )
    table = Table(title="Tracking History")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Details", style="green")

    for update in result.updates:
        table.add_row(update.timestamp, update.status, update.message)
    console.print(table)