"""
Public Infrastructure & Utilities Intelligence Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
from geopy.geocoders import Nominatim
import overpy

# Create a new Typer application for Infrastructure Intelligence commands
infrastructure_intel_app = typer.Typer(
    name="infrastructure-dependency",
    help="Public Infrastructure & Utilities Intelligence",
)

def find_nearby_substations(lat: float, lon: float, radius: int = 5000) -> list:
    """
    Finds electrical substations near a given set of coordinates using the Overpass API.
    """
    api = overpy.Overpass()
    query = f"""
    [out:json];
    (
      node["power"="substation"](around:{radius},{lat},{lon});
      way["power"="substation"](around:{radius},{lat},{lon});
      relation["power"="substation"](around:{radius},{lat},{lon});
    );
    out center;
    """
    result = api.query(query)
    
    substations = []
    for node in result.nodes:
        substations.append({
            "name": node.tags.get("name", "N/A"),
            "operator": node.tags.get("operator", "N/A"),
            "lat": float(node.lat),
            "lon": float(node.lon)
        })
    return substations

@infrastructure_intel_app.command(name="analyze", help="Analyze dependencies on public infrastructure for a given address.")
def infrastructure_dependency(
    address: Annotated[
        str,
        typer.Option(
            "--address",
            "-a",
            help="The physical address to analyze for infrastructure dependencies.",
            prompt="Enter the address to analyze",
        ),
    ]
):
    """
    Identifies and assesses the public and semi-public infrastructure that a
    target company relies on, such as power grids and utility networks.
    """
    print(f"Analyzing infrastructure dependencies for: {address}")

    try:
        # 1. Geocode the address to get its coordinates
        geolocator = Nominatim(user_agent="chimera-intel")
        location = geolocator.geocode(address)
        if not location:
            print(f"Error: Could not geocode the address '{address}'.")
            raise typer.Exit(code=1)

        lat, lon = location.latitude, location.longitude
        print(f"Coordinates found: Latitude={lat:.4f}, Longitude={lon:.4f}")

        # 2. Find nearby electrical substations
        substations = find_nearby_substations(lat, lon)

        if substations:
            print("\n--- Nearby Electrical Substations ---")
            for sub in substations:
                print(f"- Name: {sub['name']}, Operator: {sub['operator']}")
                print(f"  Coordinates: {sub['lat']:.4f}, {sub['lon']:.4f}")
            print("-------------------------------------")
        else:
            print("\nNo electrical substations found within the search radius.")
            
        # In a full implementation, you would add more functions here to query
        # for other infrastructure types like fiber optic networks, water supplies, etc.

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    infrastructure_intel_app()