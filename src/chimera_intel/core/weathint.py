"""
Weather & Environmental Intelligence (WEATHINT) Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import httpx
from geopy.geocoders import Nominatim
from rich.console import Console
from rich.panel import Panel

from chimera_intel.core.config_loader import API_KEYS, CONFIG
from chimera_intel.core.http_client import get_http_client

console = Console()

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
    console.print(f"Performing '{peril}' risk assessment for: {location}")

    try:
        # 1. Geocode the location string to get coordinates

        geolocator = Nominatim(user_agent="chimera-intel")
        location_data = geolocator.geocode(location)
        if not location_data:
            console.print(f"Error: Could not geocode location '{location}'.")
            raise typer.Exit(code=1)
        lat, lon = location_data.latitude, location_data.longitude
        console.print(f"Coordinates found: Latitude={lat:.4f}, Longitude={lon:.4f}")

        # 2. Fetch live weather data as an initial risk indicator

        with get_http_client() as client:
            weather_data = get_live_weather(lat, lon, client)
        # 3. Analyze and display results based on the specified peril

        main_weather = weather_data.get("weather", [{}])[0].get("main", "N/A")
        temp = weather_data.get("main", {}).get("temp", 0)
        humidity = weather_data.get("main", {}).get("humidity", 0)
        wind_speed = weather_data.get("wind", {}).get("speed", 0)
        rain_1h = weather_data.get("rain", {}).get("1h", 0)

        console.print("\n--- [bold green]Live Environmental Data[/bold green] ---")
        console.print(f"- Current Weather: {main_weather}")
        console.print(f"- Temperature: {temp}°C")
        console.print(f"- Humidity: {humidity}%")
        console.print(f"- Wind Speed: {wind_speed} m/s")
        console.print(f"- Rain (last 1h): {rain_1h} mm")
        console.print("-----------------------------")

        risk_assessment_summary = "Risk assessment could not be determined."
        risk_color = "white"

        if peril.lower() == "wildfire":
            # Simple Wildfire Risk: High temp, low humidity, high wind

            if temp > 30 and humidity < 30 and wind_speed > 10:
                risk_assessment_summary = "HIGH RISK: Conditions are favorable for rapid wildfire spread (High Temp, Low Humidity, High Wind)."
                risk_color = "bold red"
            elif temp > 25 and humidity < 40:
                risk_assessment_summary = "MODERATE RISK: Elevated temperature and low humidity increase wildfire risk."
                risk_color = "yellow"
            else:
                risk_assessment_summary = "LOW RISK: Current conditions are not indicative of a high wildfire threat."
                risk_color = "green"
        elif peril.lower() == "flood":
            # Simple Flood Risk: Heavy rain

            if rain_1h > 10:  # More than 10mm of rain in an hour
                risk_assessment_summary = "HIGH RISK: Heavy rainfall detected, which could lead to localized flooding."
                risk_color = "bold red"
            elif rain_1h > 2.5:
                risk_assessment_summary = "MODERATE RISK: Moderate rainfall detected. Monitor for potential flooding."
                risk_color = "yellow"
            else:
                risk_assessment_summary = "LOW RISK: No significant rainfall to indicate immediate flood risk."
                risk_color = "green"
        elif peril.lower() == "extreme-heat":
            if temp > 35:
                risk_assessment_summary = (
                    "HIGH RISK: Extreme heat warning. Temperature is above 35°C."
                )
                risk_color = "bold red"
            elif temp > 30:
                risk_assessment_summary = "MODERATE RISK: High temperature advisory. Temperature is above 30°C."
                risk_color = "yellow"
            else:
                risk_assessment_summary = (
                    "LOW RISK: Temperature is within normal range."
                )
                risk_color = "green"
        console.print(
            Panel(
                risk_assessment_summary,
                title=f"[{risk_color}]Peril Assessment: {peril.capitalize()}[/{risk_color}]",
                border_style=risk_color,
            )
        )
    except ValueError as e:
        console.print(f"Configuration Error: {e}")
        raise typer.Exit(code=1)
    except httpx.HTTPStatusError as e:
        console.print(
            f"API Error: Failed to fetch weather data. Status code: {e.response.status_code}"
        )
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"An unexpected error occurred: {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    weathint_app()
