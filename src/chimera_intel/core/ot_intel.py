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

class OTAsset:
    """Represents an Operational Technology (OT) asset."""

    def __init__(self, ip_address: str, device_id: str = None, device_type: str = None, location: str = None, vulnerabilities: list = None):
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
            print(f"Shodan API Error: {e}")
            raise
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            raise

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

    try:
        asset = OTAsset(ip_address)
        host_info = asset.collect_data()

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
            print("\n[bold green]Identified potential ICS/SCADA protocols:[/bold green]")
            for protocol in found_protocols:
                print(f"- {protocol}")
        else:
            print("\nNo common ICS/SCADA protocols identified in banner data.")
        
        print("-----------------------------")

    except (ValueError, shodan.APIError) as e:
        print(f"Error: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    ot_intel_app()