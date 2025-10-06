"""
Maritime & Shipping Intelligence (MARINT) Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import asyncio
import websockets
import json
from chimera_intel.core.config_loader import API_KEYS

# Create a new Typer application for MARINT commands

marint_app = typer.Typer(
    name="marint",
    help="Maritime & Shipping Intelligence (MARINT)",
)


async def get_vessel_data(imo: str):
    """
    Connects to the aisstream.io websocket and retrieves data for the specified vessel.
    """
    api_key = API_KEYS.aisstream_api_key
    if not api_key:
        print("Error: AISSTREAM_API_KEY not found in .env file.")
        return
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
                    print("--- Live Vessel Data ---")
                    print(f"IMO: {position_report.get('ImoNumber')}")
                    print(f"Latitude: {position_report['Latitude']}")
                    print(f"Longitude: {position_report['Longitude']}")
                    print(f"Speed Over Ground: {position_report['Sog']} knots")
                    print(f"Course Over Ground: {position_report['Cog']} degrees")
                    print("----------------------")


@marint_app.command(name="track-vessel", help="Track a vessel by its IMO number.")
def track_vessel(
    imo: Annotated[
        str,
        typer.Option(
            "--imo",
            "-i",
            help="The IMO number of the vessel to track.",
            prompt="Enter the vessel's IMO number",
        ),
    ],
):
    """
    Tracks a vessel using its IMO number by connecting to a live AIS data stream.
    """
    print(f"Starting live tracking for vessel with IMO: {imo}...")
    try:
        asyncio.run(get_vessel_data(imo))
    except KeyboardInterrupt:
        print("\nStopping vessel tracking.")


if __name__ == "__main__":
    marint_app()
