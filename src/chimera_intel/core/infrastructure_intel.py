"""
Public Infrastructure & Utilities Intelligence Module for Chimera Intel.
"""
import os 
import typer
from typing_extensions import Annotated
from geopy.geocoders import Nominatim
import overpy
import requests

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
        substations.append(
            {
                "name": node.tags.get("name", "N/A"),
                "operator": node.tags.get("operator", "N/A"),
                "lat": float(node.lat),
                "lon": float(node.lon),
            }
        )
    return substations


def find_nearby_cell_towers(lat: float, lon: float) -> list:
    """
    Finds nearby cell towers using the OpenCelliD API.
    Note: This requires an OpenCelliD API key set as an environment variable `OPENCELLID_API_KEY`.
    """
    api_key = os.getenv("OPENCELLID_API_KEY")
    if not api_key:
        print(
            "[yellow]Warning: OPENCELLID_API_KEY environment variable not set. Skipping cell tower search.[/yellow]"
        )
        return []
    url = "https://opencellid.org/cell/getInArea"
    params = {
        "key": api_key,
        "BBOX": f"{lon-0.05},{lat-0.05},{lon+0.05},{lat+0.05}",  # Create a bounding box
        "format": "json",
    }
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json().get("cells", [])
    except requests.exceptions.RequestException as e:
        print(f"[red]Error fetching cell tower data: {e}[/red]")
        return []


def find_nearby_water_sources(lat: float, lon: float, radius: int = 5000) -> list:
    """
    Finds nearby water towers and reservoirs using the Overpass API.
    """
    api = overpy.Overpass()
    query = f"""
    [out:json];
    (
      node["man_made"="water_tower"](around:{radius},{lat},{lon});
      way["natural"="water"](around:{radius},{lat},{lon});
    );
    out center;
    """
    result = api.query(query)

    water_sources = []
    for node in result.nodes:
        water_sources.append(
            {
                "type": "Water Tower",
                "name": node.tags.get("name", "N/A"),
                "lat": float(node.lat),
                "lon": float(node.lon),
            }
        )
    for way in result.ways:
        water_sources.append(
            {
                "type": "Water Body",
                "name": way.tags.get("name", "N/A"),
                "lat": float(way.center_lat),
                "lon": float(way.center_lon),
            }
        )
    return water_sources


@infrastructure_intel_app.command(
    name="analyze",
    help="Analyze dependencies on public infrastructure for a given address.",
)
def infrastructure_dependency(
    address: Annotated[
        str,
        typer.Option(
            "--address",
            "-a",
            help="The physical address to analyze for infrastructure dependencies.",
            prompt="Enter the address to analyze",
        ),
    ],
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
        # 3. Find nearby cell towers

        cell_towers = find_nearby_cell_towers(lat, lon)
        if cell_towers:
            print("\n--- Nearby Cell Towers ---")
            for tower in cell_towers[:5]:  # Limit to 5 for brevity
                print(
                    f"- MCC: {tower.get('mcc')}, MNC: {tower.get('mnc')}, LAC: {tower.get('lac')}, Cell ID: {tower.get('cellid')}"
                )
                print(f"  Coordinates: {tower.get('lat'):.4f}, {tower.get('lon'):.4f}")
            print("--------------------------")
        # 4. Find nearby water sources

        water_sources = find_nearby_water_sources(lat, lon)
        if water_sources:
            print("\n--- Nearby Water Sources ---")
            for source in water_sources:
                print(f"- Type: {source['type']}, Name: {source['name']}")
                print(f"  Coordinates: {source['lat']:.4f}, {source['lon']:.4f}")
            print("----------------------------")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    infrastructure_intel_app()
