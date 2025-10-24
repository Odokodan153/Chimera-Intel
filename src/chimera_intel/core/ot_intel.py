"""
Operational Technology (OT) & ICS/SCADA Intelligence Module for Chimera Intel.
"""

import typer
import shodan
from typing import Optional, List

from chimera_intel.core.config_loader import API_KEYS

# Create a new Typer application for OT Intelligence commands
ot_intel_app = typer.Typer(
    name="ot-intel",
    help="Operational Technology (OT) & ICS/SCADA Intelligence",
)


class OTAsset:
    """Represents an Operational Technology (OT) asset."""

    def __init__(
        self,
        ip_address: str,
        device_id: Optional[str] = None,
        device_type: Optional[str] = None,
        location: Optional[str] = None,
        vulnerabilities: Optional[List] = None,
    ):
        """
        Initializes the OTAsset with an IP address.

        Args:
            ip_address: The IP address of the OT asset.
        """
        self.ip_address = ip_address
        self.device_id = device_id
        self.device_type = device_type
        self.location = location
        self.vulnerabilities = vulnerabilities
        self.api_key = API_KEYS.shodan_api_key
        if not self.api_key:
            raise ValueError("SHODAN_API_KEY not found in .env file.")
        self.api = shodan.Shodan(self.api_key)

    def collect_data(self) -> dict:
        """
        Collects data about the OT asset from Shodan.

        Returns:
            A dictionary containing the host information from Shodan.
        """
        try:
            host_info = self.api.host(self.ip_address)
            return host_info
        except shodan.APIError as e:
            # Re-raise to be caught by the command handler
            raise e


@ot_intel_app.command(
    name="recon", help="Perform reconnaissance on an IP address for OT systems."
)
def ot_recon(
    # --- FIX: Changed from typer.Argument to typer.Option ---
    ip_address: str = typer.Option(
        ..., 
        "--ip-address",
        help="The IP address to scan for OT protocols."
    ),
):
    """
    Uses Shodan to find exposed industrial protocols and other OT-related
    information for a given IP address.
    """
    typer.echo(f"Performing OT reconnaissance on: {ip_address}")

    try:
        asset = OTAsset(ip_address)
        host_info = asset.collect_data()

        typer.echo("\n--- Shodan Host Information ---")
        typer.echo(f"IP: {host_info.get('ip_str')}")
        typer.echo(f"Organization: {host_info.get('org', 'N/A')}")
        typer.echo(
            f"Location: {host_info.get('city', 'N/A')}, {host_info.get('country_name', 'N/A')}"
        )
        typer.echo(f"Open Ports: {', '.join(map(str, host_info.get('ports', [])))}")

        # Filter for common ICS/SCADA protocols
        ics_protocols = {"modbus", "s7", "bacnet", "dnp3", "ethernet/ip"}
        found_protocols = set()

        for item in host_info.get("data", []):
            for protocol in ics_protocols:
                if (
                    protocol in item.get("data", "").lower()
                    or protocol in (item.get("product") or "").lower()
                ):
                    found_protocols.add(protocol.upper())
        if found_protocols:
            typer.echo(
                "\n[bold green]Identified potential ICS/SCADA protocols:[/bold green]"
            )
            for protocol in found_protocols:
                typer.echo(f"- {protocol}")
        else:
            typer.echo("\nNo common ICS/SCADA protocols identified in banner data.")
        typer.echo("-----------------------------")

        # FIX: Add explicit success exit for the test runner
        # REMOVED: raise typer.Exit(code=0)
        
    except (ValueError, shodan.APIError) as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)

    # --- FIX: Moved success exit outside the try/except block ---
    # This prevents it from being caught by 'except Exception'
    raise typer.Exit(code=0)
    # --- END FIX ---


if __name__ == "__main__":
    ot_intel_app()