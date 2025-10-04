import typer
import requests
import os
from rich.console import Console
from rich.table import Table
from datetime import datetime

app = typer.Typer(
    no_args_is_help=True,
    help="Ecological & Sustainability Intelligence (ECOINT) tools.",
)
console = Console()


class EcoInt:
    """
    Handles ECOINT tasks using live data from public APIs.
    """

    def __init__(self):
        self.epa_base_url = (
            "https://enviro.epa.gov/facts/services/echo/cwa_rest_services"
        )
        self.climatetrace_url = "https://api.climatetrace.org/v4/assets"
        # It's recommended to manage API keys via environment variables

        self.climatetrace_api_key = os.getenv("CLIMATETRACE_API_KEY")

    def get_epa_violations(self, company_name: str) -> list:
        """
        Fetches Clean Water Act (CWA) compliance and enforcement data from the EPA.
        """
        try:
            # This query is designed to be broad; a more specific query might use a PCOMP_NAME

            response = requests.get(
                f"{self.epa_base_url}.get_facilities",
                params={"output": "JSON", "p_fn": company_name},
            )
            response.raise_for_status()
            data = response.json()

            facilities = data.get("Results", {}).get("Facilities", [])
            violations = []
            for facility in facilities:
                violations.append(
                    {
                        "facility_name": facility.get("CWPName"),
                        "address": f"{facility.get('CWPStreet')}, {facility.get('CWPCity')}, {facility.get('CWPState')}",
                        "last_inspection_date": facility.get("LastInspectDate"),
                        "formal_actions_last_5_years": facility.get("CWPFormalCount"),
                        "penalties_last_5_years_usd": facility.get("CWPPenaltyCount"),
                    }
                )
            return violations
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red]Error fetching EPA data: {e}[/bold red]")
            return []

    def get_ghg_emissions(self, company_name: str) -> list:
        """
        Fetches asset-level GHG emissions data from Climate TRACE.
        Note: This requires an API key and searches by asset name, not directly by company.
        """
        if not self.climatetrace_api_key:
            console.print(
                "[bold yellow]CLIMATETRACE_API_KEY environment variable not set. Cannot fetch GHG data.[/bold yellow]"
            )
            return []
        headers = {"Authorization": f"Bearer {self.climatetrace_api_key}"}
        try:
            response = requests.get(
                self.climatetrace_url,
                headers=headers,
                params={"q": company_name, "limit": 10},
            )
            response.raise_for_status()
            data = response.json()

            assets = data.get("assets", [])
            emissions_data = []
            for asset in assets:
                # Find the most recent emissions data

                latest_emissions = max(
                    asset.get("emissions", []), key=lambda x: x["year"], default=None
                )
                if latest_emissions:
                    emissions_data.append(
                        {
                            "asset_name": asset.get("name"),
                            "country": asset.get("country"),
                            "sector": asset.get("sector"),
                            "year": latest_emissions.get("year"),
                            "co2e_tonnes": latest_emissions.get("emissions_quantity"),
                        }
                    )
            return emissions_data
        except requests.exceptions.RequestException as e:
            console.print(
                f"[bold red]Error fetching Climate TRACE data: {e}[/bold red]"
            )
            return []


@app.command(name="epa-violations")
def epa_violations(
    company_name: str = typer.Argument(
        ..., help="The target company name to search for in EPA records."
    )
):
    """Looks up Clean Water Act violations from the EPA for a given company."""
    ecoint = EcoInt()
    violations = ecoint.get_epa_violations(company_name)

    if not violations:
        console.print(f"[yellow]No EPA violations found for '{company_name}'.[/yellow]")
        return
    table = Table(
        title=f"EPA Clean Water Act Violations Associated with '{company_name}'"
    )
    table.add_column("Facility Name", style="cyan")
    table.add_column("Address", style="white")
    table.add_column("Last Inspection", style="yellow")
    table.add_column("Formal Actions (5yr)", style="magenta")
    table.add_column("Penalties (5yr, USD)", style="red")

    for v in violations:
        table.add_row(
            v["facility_name"],
            v["address"],
            v["last_inspection_date"],
            str(v["formal_actions_last_5_years"]),
            str(v["penalties_last_5_years_usd"]),
        )
    console.print(table)


@app.command(name="ghg-emissions")
def ghg_emissions(
    company_name: str = typer.Argument(
        ..., help="Company or asset name to search for GHG emissions."
    )
):
    """Fetches asset-level GHG emissions from Climate TRACE."""
    ecoint = EcoInt()
    emissions = ecoint.get_ghg_emissions(company_name)

    if not emissions:
        console.print(
            f"[yellow]No GHG emissions data found for '{company_name}'. This may be due to naming discrepancies.[/yellow]"
        )
        return
    table = Table(
        title=f"GHG Emissions for Assets Associated with '{company_name}' (from Climate TRACE)"
    )
    table.add_column("Asset Name", style="cyan")
    table.add_column("Country", style="white")
    table.add_column("Sector", style="yellow")
    table.add_column("Year", style="magenta")
    table.add_column("CO2e (Tonnes)", style="red")

    for e in emissions:
        table.add_row(
            e["asset_name"],
            e["country"],
            e["sector"],
            str(e["year"]),
            f"{e['co2e_tonnes']:,}",
        )
    console.print(table)


if __name__ == "__main__":
    app()
