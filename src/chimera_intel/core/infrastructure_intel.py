"""
Public Infrastructure & Utilities Intelligence Module for Chimera Intel.

Finds dependencies on critical infrastructure like power, water, communications,
and logistics hubs (ports, airports).
"""

import os
import typer
from typing_extensions import Annotated
from geopy.geocoders import Nominatim
import overpy
import requests
from rich.console import Console

# Create a rich console

console = Console()

# Create a new Typer application for Infrastructure Intelligence commands

infrastructure_intel_app = typer.Typer(
    name="infrastructure-dependency",
    help="Public Infrastructure & Utilities Intelligence",
)


def find_nearby_substations(
    api: overpy.Overpass, lat: float, lon: float, radius: int = 5000
) -> list:
    """
    Finds electrical substations near a given set of coordinates using the Overpass API.
    """
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
                "type": "Substation",
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
        console.print(
            "Warning: OPENCELLID_API_KEY environment variable not set. Skipping cell tower search.",
            style="yellow",
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
        console.print(f"Error fetching cell tower data: {e}", style="red")
        return []


def find_nearby_water_sources(
    api: overpy.Overpass, lat: float, lon: float, radius: int = 5000
) -> list:
    """
    Finds nearby water towers and reservoirs using the Overpass API.
    """
    query = f"""
    [out:json];
    (
      node["man_made"="water_tower"](around:{radius},{lat},{lon});
      way["natural"="water"](around:{radius},{lat},{lon});
      way["landuse"="reservoir"](around:{radius},{lat},{lon});
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
                "type": "Water Body"
                if way.tags.get("natural") == "water"
                else "Reservoir",
                "name": way.tags.get("name", "N/A"),
                "lat": float(way.center_lat),
                "lon": float(way.center_lon),
            }
        )
    return water_sources


# --- NEW FUNCTION ---

def find_nearby_airports(
    api: overpy.Overpass, lat: float, lon: float, radius: int = 25000
) -> list:
    """
    Finds airports and major aerodromes near coordinates using the Overpass API.
    (Search radius is larger by default)
    """
    query = f"""
    [out:json];
    (
      node["aeroway"="aerodrome"](around:{radius},{lat},{lon});
      way["aeroway"="aerodrome"](around:{radius},{lat},{lon});
    );
    out center;
    """
    result = api.query(query)
    airports = []
    for item in result.nodes + result.ways:
        airports.append(
            {
                "type": "Airport/Aerodrome",
                "name": item.tags.get("name", "N/A"),
                "iata": item.tags.get("iata", "N/A"),
                "lat": float(item.lat if item.is_node else item.center_lat),
                "lon": float(item.lon if item.is_node else item.center_lon),
            }
        )
    return airports


# --- NEW FUNCTION ---

def find_nearby_ports(
    api: overpy.Overpass, lat: float, lon: float, radius: int = 25000
) -> list:
    """
    Finds maritime ports and harbours near coordinates using the Overpass API.
    (Search radius is larger by default)
    """
    query = f"""
    [out:json];
    (
      node["landuse"="port"](around:{radius},{lat},{lon});
      way["landuse"="port"](around:{radius},{lat},{lon});
      node["harbour"="yes"](around:{radius},{lat},{lon});
      way["harbour"="yes"](around:{radius},{lat},{lon});
    );
    out center;
    """
    result = api.query(query)
    ports = []
    for item in result.nodes + result.ways:
        ports.append(
            {
                "type": "Port/Harbour",
                "name": item.tags.get("name", "N/A"),
                "lat": float(item.lat if item.is_node else item.center_lat),
                "lon": float(item.lon if item.is_node else item.center_lon),
            }
        )
    return ports


@infrastructure_intel_app.command(
    name="analyze",
    help="Analyze dependencies on public infrastructure for a given address.",
)
def infrastructure_dependency(
    address: Annotated[
        str,
        typer.Argument(
            help="The physical address to analyze for infrastructure dependencies.",
        ),
    ],
    radius: int = typer.Option(
        5000, "--radius", "-r", help="Search radius in meters for most utilities."
    ),
    logistics_radius: int = typer.Option(
        25000,
        "--logistics-radius",
        "-l",
        help="Larger search radius for ports/airports (in meters).",
    ),
):
    """
    Identifies and assesses the public and semi-public infrastructure that a
    target company relies on, such as power, water, comms, ports, and airports.
    """
    console.print(f"Analyzing infrastructure dependencies for: {address}", style="bold")

    try:
        # 1. Geocode the address to get its coordinates

        geolocator = Nominatim(user_agent="chimera-intel")
        location = geolocator.geocode(address)
        if not location:
            console.print(
                f"Error: Could not geocode the address '{address}'.", style="red"
            )
            raise typer.Exit(code=1)
        lat, lon = location.latitude, location.longitude
        console.print(
            f"Coordinates found: Latitude={lat:.4f}, Longitude={lon:.4f}",
            style="green",
        )

        # Initialize Overpass API

        api = overpy.Overpass()

        # 2. Find nearby electrical substations

        with console.status(
            "[cyan]Searching for electrical infrastructure...[/cyan]"
        ):
            substations = find_nearby_substations(api, lat, lon, radius=radius)
        if substations:
            console.print("\n--- Nearby Electrical Substations ---", style="bold yellow")
            for sub in substations:
                console.print(f"- Name: {sub['name']}, Operator: {sub['operator']}")
                console.print(f"  Coordinates: {sub['lat']:.4f}, {sub['lon']:.4f}")
        else:
            console.print(
                "\nNo electrical substations found within the search radius."
            )

        # 3. Find nearby cell towers

        with console.status("[cyan]Searching for cell towers...[/cyan]"):
            cell_towers = find_nearby_cell_towers(lat, lon)
        if cell_towers:
            console.print("\n--- Nearby Cell Towers ---", style="bold yellow")
            for tower in cell_towers[:5]:  # Limit to 5 for brevity
                console.print(
                    f"- MCC: {tower.get('mcc')}, MNC: {tower.get('mnc')}, LAC: {tower.get('lac')}, Cell ID: {tower.get('cellid')}"
                )
                console.print(
                    f"  Coordinates: {tower.get('lat'):.4f}, {tower.get('lon'):.4f}"
                )
        # 4. Find nearby water sources

        with console.status("[cyan]Searching for water sources...[/cyan]"):
            water_sources = find_nearby_water_sources(api, lat, lon, radius=radius)
        if water_sources:
            console.print("\n--- Nearby Water Sources ---", style="bold yellow")
            for source in water_sources:
                console.print(f"- Type: {source['type']}, Name: {source['name']}")
                console.print(
                    f"  Coordinates: {source['lat']:.4f}, {source['lon']:.4f}"
                )

        # 5. Find nearby airports (NEW)

        with console.status("[cyan]Searching for airports...[/cyan]"):
            airports = find_nearby_airports(api, lat, lon, radius=logistics_radius)
        if airports:
            console.print("\n--- Nearby Airports ---", style="bold yellow")
            for port in airports:
                console.print(
                    f"- Name: {port['name']}, IATA Code: {port.get('iata', 'N/A')}"
                )
                console.print(f"  Coordinates: {port['lat']:.4f}, {port['lon']:.4f}")
        else:
            console.print("\nNo airports found within the search radius.")

        # 6. Find nearby ports (NEW)

        with console.status("[cyan]Searching for ports/harbours...[/cyan]"):
            ports = find_nearby_ports(api, lat, lon, radius=logistics_radius)
        if ports:
            console.print("\n--- Nearby Ports/Harbours ---", style="bold yellow")
            for port in ports:
                console.print(f"- Name: {port['name']}")
                console.print(f"  Coordinates: {port['lat']:.4f}, {port['lon']:.4f}")
        else:
            console.print("\nNo ports or harbours found within the search radius.")
        console.print("\n" + "-" * 30, style="bold")

    except Exception as e:
        console.print(f"An unexpected error occurred: {e}", style="red")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    infrastructure_intel_app()