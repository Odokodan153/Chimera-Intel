"""
WEATHINT (Weather Intelligence) Module for Chimera Intel.

Provides functionalities to retrieve and analyze weather data for a given location,
which can be crucial for physical security assessments and operational planning.
"""

import typer
from typing import Optional, Dict, Any
from geopy.geocoders import Nominatim
from rich.panel import Panel
import httpx

from .config_loader import API_KEYS
from .utils import console

weathint_app = typer.Typer(
    name="weathint",
    help="Performs Weather Intelligence (WEATHINT) tasks.",
)


def get_coordinates(location_name: str) -> Optional[Dict[str, float]]:
    """Geocodes a location name to get its latitude and longitude."""
    geolocator = Nominatim(user_agent="chimera-intel")
    try:
        location = geolocator.geocode(location_name)
        if location:
            return {"latitude": location.latitude, "longitude": location.longitude}
    except Exception as e:
        console.print(f"[bold red]Geocoding failed:[/bold red] {e}")
    return None


def get_weather_forecast(lat: float, lon: float) -> Optional[Dict[str, Any]]:
    """Retrieves the weather forecast from OpenWeatherMap API."""
    if not API_KEYS.openweathermap_api_key:
        console.print("[bold red]OpenWeatherMap API key not configured.[/bold red]")
        return None
    url = "https://api.openweathermap.org/data/2.5/weather"
    params: Dict[str, Any] = {
        "lat": lat,
        "lon": lon,
        "appid": API_KEYS.openweathermap_api_key,
        "units": "metric",  # Use Celsius
    }

    try:
        with httpx.Client() as client:
            response = client.get(url, params=params)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        console.print(
            f"[bold red]Weather API request failed:[/bold red] {e.response.text}"
        )
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")
    return None


@weathint_app.command("get")
def get_weather(
    location: str = typer.Argument(
        ..., help="The city and country (e.g., 'Paris, France')."
    ),
):
    """
    Retrieves the current weather for a specified location.
    """
    console.print(f"[bold cyan]Fetching weather for {location}...[/bold cyan]")

    coords = get_coordinates(location)
    if not coords:
        console.print(
            f"[bold red]Could not find coordinates for {location}.[/bold red]"
        )
        raise typer.Exit(code=1)
    weather_data = get_weather_forecast(coords["latitude"], coords["longitude"])

    if not weather_data:
        raise typer.Exit(code=1)
    # Format and display the weather data

    main_weather = weather_data.get("weather", [{}])[0].get("main", "N/A")
    description = weather_data.get("weather", [{}])[0].get("description", "N/A")
    temp = weather_data.get("main", {}).get("temp", "N/A")
    feels_like = weather_data.get("main", {}).get("feels_like", "N/A")
    wind_speed = weather_data.get("wind", {}).get("speed", "N/A")

    report = (
        f"Weather: {main_weather} ({description})\n"
        f"Temperature: {temp}°C (Feels like: {feels_like}°C)\n"
        f"Wind Speed: {wind_speed} m/s"
    )
    console.print(
        Panel(
            report,
            title=f"[bold green]Current Weather in {location}[/bold green]",
            border_style="green",
        )
    )
