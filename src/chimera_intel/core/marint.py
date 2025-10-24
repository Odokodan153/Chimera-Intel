"""
Maritime & Shipping Intelligence (MARINT) Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import asyncio
import websockets
import json
# import sys  <-- FIX: Removed sys import
from chimera_intel.core.config_loader import API_KEYS

# Create a new Typer application for MARINT commands
marint_app = typer.Typer(
    name="marint",
    help="Maritime & Shipping Intelligence (MARINT)",
)


async def get_vessel_data(imo: str, api_key: str, test_mode: bool = False):  # MODIFIED: Added api_key param
    """
    Connects to the aisstream.io websocket and retrieves data for the specified vessel.
    """
    # MODIFIED: Removed API key check, as it's now done in the CLI function
    async with websockets.connect("wss://stream.aisstream.io/v0/stream") as websocket:
        subscribe_message = {
            "APIKey": api_key,
            "BoundingBoxes": [[[-180, -90], [180, 90]]],
            "FiltersShipMMSI": [],
            "FilterMessageTypes": ["PositionReport"],
        }
        await websocket.send(json.dumps(subscribe_message))

        async for message_json in websocket:
            message = json.loads(message_json)
            message_type = message["MessageType"]

            if message_type == "PositionReport":
                position_report = message["Message"]["PositionReport"]
                if str(position_report.get("ImoNumber")) == imo:
                    typer.echo("--- Live Vessel Data ---")
                    typer.echo(f"IMO: {position_report.get('ImoNumber')}")
                    typer.echo(f"Latitude: {position_report['Latitude']}")
                    typer.echo(f"Longitude: {position_report['Longitude']}")
                    typer.echo(f"Speed Over Ground: {position_report['Sog']} knots")
                    typer.echo(f"Course Over Ground: {position_report['Cog']} degrees")
                    typer.echo("----------------------")
                    if test_mode:
                        break  # Exit after one message in test mode


@marint_app.command(name="track-vessel", help="Track a vessel by its IMO number.")
def track_vessel(
    # --- FIX: Changed from Option to Argument to match test invocation ---
    imo: Annotated[
        str,
        typer.Argument(  # <-- This is the fix
            help="The IMO number of the vessel to track."
        ),
    ],
    # --- End fix ---
    test: bool = typer.Option(False, "--test", ...),
):
    """
    Tracks a vessel using its IMO number by connecting to a live AIS data stream.
    """
    # --- FIX: Removed the manual prompt block ---
    # if imo is None:
    #     imo = typer.prompt("Enter the vessel's IMO number")
    # --- End fix ---

    # --- MODIFIED: API key check moved here ---
    api_key = API_KEYS.aisstream_api_key
    if not api_key:
        typer.echo("Error: AISSTREAM_API_KEY not found in .env file.", err=True)
        # FIX: Use typer.Exit(code=1)
        raise typer.Exit(code=1)
    # --- End modification ---

    typer.echo(f"Starting live tracking for vessel with IMO: {imo}...")
    try:
        # MODIFIED: Pass api_key to the async function
        asyncio.run(get_vessel_data(imo, api_key=api_key, test_mode=test))
        
        # FIX: Add explicit typer.Exit(code=0) for success
        raise typer.Exit(code=0)
        
    except ValueError as e:
        # This will now catch other ValueErrors, but not the API key one.
        typer.echo(f"Error: {e}", err=True)
        # FIX: Use typer.Exit(code=1)
        raise typer.Exit(code=1)
    except KeyboardInterrupt:
        typer.echo("\nStopping vessel tracking.")
        # FIX: Use typer.Exit(code=0)
        raise typer.Exit(code=0) 
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        # FIX: Use typer.Exit(code=1)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    marint_app()
