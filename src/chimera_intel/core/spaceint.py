"""Space Intelligence (SPACEINT) tools for tracking satellites, monitoring launches, and predicting flyovers."""

import typer
import requests
from datetime import datetime, timedelta
from sgp4.api import Satrec, jday
from rich.console import Console
from rich.table import Table
from skyfield.api import load, Topos, EarthSatellite

app = typer.Typer(no_args_is_help=True, help="Space Intelligence (SPACEINT) tools.")
console = Console()


class SpaceInt:
    """
    A class to handle Space Intelligence (SPACEINT) tasks such as tracking satellites,
    monitoring launches, and predicting satellite flyovers.
    """

    def __init__(self):
        self.celestrak_url = "https://celestrak.org/NORAD/elements/gp.php?CATNR={norad_cat_id}&FORMAT=tle"
        self.launch_api_url = "https://ll.thespacedevs.com/2.2.0/launch/upcoming/"
        self.ts = load.timescale()

    def get_satellite_tle(self, norad_cat_id: int) -> tuple[str, str, str] | None:
        """
        Retrieves the Two-Line Element (TLE) data for a satellite from CelesTrak.
        """
        try:
            response = requests.get(
                self.celestrak_url.format(norad_cat_id=norad_cat_id)
            )
            response.raise_for_status()
            tle_data = response.text.strip().splitlines()
            if len(tle_data) >= 3:
                return tle_data[0].strip(), tle_data[1].strip(), tle_data[2].strip()
            return None
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red]Error fetching TLE data: {e}[/bold red]")
            return None

    def get_satellite_position(
        self, tle_line1: str, tle_line2: str
    ) -> tuple[float, float, float] | None:
        """
        Calculates the current position and velocity of a satellite from its TLE data.
        """
        try:
            satellite = Satrec.twoline2rv(tle_line1, tle_line2)
            jd, fr = jday(
                datetime.utcnow().year,
                datetime.utcnow().month,
                datetime.utcnow().day,
                datetime.utcnow().hour,
                datetime.utcnow().minute,
                datetime.utcnow().second,
            )
            e, r, v = satellite.sgp4(jd, fr)
            if e == 0:
                return r
            return None
        except Exception as e:
            console.print(
                f"[bold red]Error calculating satellite position: {e}[/bold red]"
            )
            return None

    def predict_flyover(
        self,
        norad_cat_id: int,
        observer_lat: float,
        observer_lon: float,
        hours: int = 24,
    ):
        """
        Predicts satellite flyovers for a given observer location using the Skyfield library.
        """
        tle = self.get_satellite_tle(norad_cat_id)
        if not tle:
            return
        name, line1, line2 = tle
        satellite = EarthSatellite(line1, line2, name, self.ts)
        observer = Topos(latitude_degrees=observer_lat, longitude_degrees=observer_lon)

        t0 = self.ts.now()
        t1 = self.ts.utc(t0.utc_datetime() + timedelta(hours=hours))

        times, events = satellite.find_events(observer, t0, t1, altitude_degrees=10.0)
        event_names = {0: "Rise", 1: "Culminate", 2: "Set"}

        table = Table(
            title=f"Flyover Predictions for {name} (NORAD ID: {norad_cat_id})"
        )
        table.add_column("Time (UTC)", style="cyan")
        table.add_column("Event", style="magenta")
        table.add_column("Altitude", style="green")
        table.add_column("Azimuth", style="yellow")

        for ti, event in zip(times, events):
            alt, az, _ = (satellite - observer).at(ti).altaz()
            table.add_row(
                ti.utc_strftime("%Y-%m-%d %H:%M:%S"),
                event_names[event],
                f"{alt.degrees:.2f}°",
                f"{az.degrees:.2f}°",
            )
        console.print(table)


@app.command()
def track(
    norad_id: int = typer.Argument(
        ..., help="The NORAD Catalog Number of the satellite to track."
    ),
):
    """
    Tracks a satellite by its NORAD ID and displays its current position.
    """
    spaceint = SpaceInt()
    console.print(
        f"[bold cyan]Fetching TLE data for NORAD ID: {norad_id}...[/bold cyan]"
    )
    tle = spaceint.get_satellite_tle(norad_id)
    if tle:
        name, line1, line2 = tle
        console.print(f"[green]Successfully fetched TLE for: {name}[/green]")
        position = spaceint.get_satellite_position(line1, line2)
        if position:
            table = Table(title=f"Current Position of {name} (NORAD ID: {norad_id})")
            table.add_column("ECI Coordinate", style="magenta")
            table.add_column("Value (km)", style="cyan")
            table.add_row("X", f"{position[0]:.2f}")
            table.add_row("Y", f"{position[1]:.2f}")
            table.add_row("Z", f"{position[2]:.2f}")
            console.print(table)
        else:
            console.print(
                "[bold red]Could not calculate satellite position.[/bold red]"
            )


@app.command()
def launches(
    limit: int = typer.Option(
        5, "--limit", "-l", help="The number of upcoming launches to display."
    ),
):
    """
    Displays a list of upcoming rocket launches.
    """
    spaceint = SpaceInt()
    try:
        response = requests.get(spaceint.launch_api_url, params={"limit": limit})
        response.raise_for_status()
        launch_data = response.json()

        table = Table(title="Upcoming Rocket Launches")
        table.add_column("Launch Time (UTC)", style="cyan")
        table.add_column("Rocket", style="magenta")
        table.add_column("Mission", style="green")
        table.add_column("Launch Pad", style="yellow")

        for launch in launch_data.get("results", []):
            table.add_row(
                launch.get("net"),
                launch.get("rocket", {}).get("configuration", {}).get("full_name"),
                launch.get("mission", {}).get("name"),
                launch.get("pad", {}).get("name"),
            )
        console.print(table)

    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error fetching launch data: {e}[/bold red]")


@app.command()
def predict(
    norad_id: int = typer.Argument(
        ..., help="The NORAD Catalog Number of the satellite."
    ),
    lat: float = typer.Option(..., "--lat", help="Observer latitude."),
    lon: float = typer.Option(..., "--lon", help="Observer longitude."),
    hours: int = typer.Option(
        24, "--hours", "-h", help="Number of hours to predict ahead."
    ),
):
    """
    Predicts satellite flyover times for a given location.
    """
    spaceint = SpaceInt()
    spaceint.predict_flyover(norad_id, lat, lon, hours)


if __name__ == "__main__":
    app()
