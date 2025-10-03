"""
Operational Technology (OT) & ICS/SCADA Intelligence Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import shodan

from chimera_intel.core.config_loader import API_KEYS

# Create a new Typer application for OT Intelligence commands
ot_intel_app = typer.Typer(
    name="ot-intel",
    help="Operational Technology (OT) & ICS/SCADA Intelligence",
)

@ot_intel_app.command(name="recon", help="Perform reconnaissance on an IP address for OT systems.")
def ot_recon(
    ip_address: Annotated[
        str,
        typer.Option(
            "--ip",
            "-i",
            help="The IP address to scan for OT protocols.",
            prompt="Enter the IP address for OT reconnaissance",
        ),
    ]
):
    """
    Uses Shodan to find exposed industrial protocols and other OT-related
    information for a given IP address.
    """
    print(f"Performing OT reconnaissance on: {ip_address}")

    api_key = API_KEYS.shodan_api_key
    if not api_key:
        print("Error: SHODAN_API_KEY not found in .env file.")
        raise typer.Exit(code=1)

    try:
        api = shodan.Shodan(api_key)
        host_info = api.host(ip_address)

        print("\n--- Shodan Host Information ---")
        print(f"IP: {host_info.get('ip_str')}")
        print(f"Organization: {host_info.get('org', 'N/A')}")
        print(f"Location: {host_info.get('city', 'N/A')}, {host_info.get('country_name', 'N/A')}")
        print(f"Open Ports: {', '.join(map(str, host_info.get('ports', [])))}")

        # Filter for common ICS/SCADA protocols
        ics_protocols = {'modbus', 's7', 'bacnet', 'dnp3', 'ethernet/ip'}
        found_protocols = set()

        for item in host_info.get('data', []):
            for protocol in ics_protocols:
                if protocol in item.get('data', '').lower() or protocol in (item.get('product') or '').lower():
                    found_protocols.add(protocol.upper())

        if found_protocols:
            print(f"\n[bold green]Identified potential ICS/SCADA protocols:[/bold green]")
            for protocol in found_protocols:
                print(f"- {protocol}")
        else:
            print("\nNo common ICS/SCADA protocols identified in banner data.")
        
        print("-----------------------------")

    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    ot_intel_app()