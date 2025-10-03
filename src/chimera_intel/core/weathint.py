"""
Weather & Environmental Intelligence (WEATHINT) Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import httpx
from geopy.geocoders import Nominatim

from chimera_intel.core.config_loader import API_KEYS, CONFIG
from chimera_intel.core.http_client import get_http_client

# Create a new Typer application for WEATHINT commands

weathint_app = typer.Typer(
    name="weathint",
    help="Weather & Environmental Intelligence (WEATHINT)",
)


def get_live_weather(lat: float, lon: float, client: httpx.Client) -> dict:
    """Fetches live weather data from OpenWeatherMap."""
    api_key = API_KEYS.openweathermap_api_key
    if not api_key:
        raise ValueError("OPENWEATHERMAP_API_KEY not found in .env file.")
    url = "https://api.openweathermap.org/data/2.5/weather"
    params = {
        "lat": lat,
        "lon": lon,
        "appid": api_key,
        "units": "metric",  # Use metric units
    }
    response = client.get(url, params=params)
    response.raise_for_status()
    return response.json()


@weathint_app.command(
    name="risk-assessment",
    help="Perform a risk assessment for a given location and peril.",
)
def risk_assessment(
    location: Annotated[
        str,
        typer.Option(
            "--location",
            "-l",
            help="The physical address or location to assess.",
            prompt="Enter the location to assess",
        ),
    ],
    peril: Annotated[
        str,
        typer.Option(
            "--peril",
            "-p",
            help="The specific peril to assess (e.g., wildfire, flood, extreme-heat).",
            prompt="Enter the peril to assess",
        ),
    ],
):
    """
    Performs a basic risk assessment by fetching live weather data.
    A full implementation would correlate this with historical data and peril maps.
    """
    print(f"Performing '{peril}' risk assessment for: {location}")

    try:
        # 1. Geocode the location string to get coordinates

        geolocator = Nominatim(user_agent="chimera-intel")
        location_data = geolocator.geocode(location)
        if not location_data:
            print(f"Error: Could not geocode location '{location}'.")
            raise typer.Exit(code=1)
        lat, lon = location_data.latitude, location_data.longitude
        print(f"Coordinates found: Latitude={lat:.4f}, Longitude={lon:.4f}")

        # 2. Fetch live weather data as an initial risk indicator

        with get_http_client() as client:
            weather_data = get_live_weather(lat, lon, client)
        # 3. Analyze and display results (this is a simplified example)

        main_weather = weather_data.get("weather", [{}])[0].get("main", "N/A")
        temp = weather_data.get("main", {}).get("temp", "N/A")
        wind_speed = weather_data.get("wind", {}).get("speed", "N/A")

        print("\n--- Live Environmental Data ---")
        print(f"Current Weather: {main_weather}")
        print(f"Temperature: {temp}°C")
        print(f"Wind Speed: {wind_speed} m/s")
        print("-----------------------------")

        # Placeholder for more advanced peril-specific analysis

        print(
            f"\nNote: A full '{peril}' assessment would involve historical data and risk maps."
        )
    except ValueError as e:
        print(f"Configuration Error: {e}")
        raise typer.Exit(code=1)
    except httpx.HTTPStatusError as e:
        print(
            f"API Error: Failed to fetch weather data. Status code: {e.response.status_code}"
        )
        raise typer.Exit(code=1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    weathint_app()
