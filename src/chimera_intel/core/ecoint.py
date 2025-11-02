import typer
import requests
import os
from rich.console import Console
from rich.table import Table
from typing import Optional, List, Dict, Any  # +++ UPDATED IMPORT
import pandas as pd  # +++ NEW IMPORT
from datetime import datetime, timedelta  # +++ NEW IMPORT

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

        # +++ NEW ATTRIBUTES (REAL API) +++
        self.comtrade_api_url = "https://comtrade.un.org/api/get"
        self.comtrade_api_key = os.getenv("COMTRADE_API_KEY")

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
                params={"q": company_name, "limit": "10"},
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

    # +++ NEW METHOD (REAL IMPLEMENTATION) +++
    def monitor_trade_flows(
        self, commodity_code: str, country_code: str = "1", # 1 = USA, "all" = world
    ) -> Dict[str, Any]:
        """
        Tracks trade data for a specific commodity from UN Comtrade
        and detects anomalies in the last 2 months vs. the 12-month average.

        Args:
            commodity_code (str): The HS commodity code (e.g., "270900" for Petroleum).
            country_code (str): The UN country code (e.g., "842" for USA). "1" is a placeholder for "USA" in some contexts, but "all" is better for global. Let's use "842".
        """
        if not self.comtrade_api_key:
            return {
                "error": "COMTRADE_API_KEY environment variable not set. Cannot fetch trade data."
            }

        # Get last 12 months (e.g., "202410,202409,202408...")
        now = datetime.now()
        periods = [
            (now - timedelta(days=i * 30)).strftime("%Y%m") for i in range(12, 0, -1)
        ]
        
        params = {
            "r": country_code,       # Reporter country
            "p": "all",              # Partner country
            "ps": ",".join(periods), # Time periods
            "cmd": commodity_code,   # Commodity code
            "token": self.comtrade_api_key,
            "fmt": "json",
            "rg": "1", # Imports
        }

        try:
            with console.status(f"[bold cyan]Fetching 12-month trade data for HS:{commodity_code}...[/bold cyan]"):
                response = requests.get(self.comtrade_api_url, params=params)
                response.raise_for_status()
            
            data = response.json().get("dataset", [])
            if not data:
                return {"error": f"No data found for commodity {commodity_code} and country {country_code}."}

            # Process data into a DataFrame
            records = []
            for r in data:
                records.append({
                    "period": r.get("pf"), # Period
                    "value_usd": r.get("TradeValue"),
                })
            
            df = pd.DataFrame(records)
            df["period"] = pd.to_numeric(df["period"])
            df["value_usd"] = pd.to_numeric(df["value_usd"])
            
            # Group by period in case of multiple partners
            df_monthly = df.groupby("period")["value_usd"].sum().reset_index()
            df_monthly = df_monthly.sort_values(by="period")

            if len(df_monthly) < 3: # Need at least 3 data points
                return {"error": "Insufficient historical data to perform analysis."}

            # Calculate rolling average and std dev (Bollinger Bands)
            df_monthly["rolling_mean"] = df_monthly["value_usd"].rolling(window=12, min_periods=3).mean()
            df_monthly["rolling_std"] = df_monthly["value_usd"].rolling(window=12, min_periods=3).std()
            
            # Shift mean/std to use as a baseline for the *current* month
            df_monthly["baseline_mean"] = df_monthly["rolling_mean"].shift(1)
            df_monthly["baseline_std"] = df_monthly["rolling_std"].shift(1)

            # Calculate Z-score
            df_monthly["z_score"] = (df_monthly["value_usd"] - df_monthly["baseline_mean"]) / df_monthly["baseline_std"]
            
            # Find anomalies (Z-score > 2 or < -2)
            anomalies = df_monthly[
                (df_monthly["z_score"] > 2.0) | (df_monthly["z_score"] < -2.0)
            ]

            latest_period = df_monthly.iloc[-1]
            
            return {
                "commodity_code": commodity_code,
                "country_code": country_code,
                "latest_period": latest_period.to_dict(),
                "anomalies_detected": anomalies.to_dict("records"),
                "analysis": f"Latest period {latest_period['period']} has a Z-score of {latest_period['z_score']:.2f}.",
                "error": None
            }

        except requests.exceptions.RequestException as e:
            return {"error": f"Error fetching trade data: {e}"}
        except Exception as e:
            return {"error": f"Error processing trade data: {e}"}


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


# +++ NEW COMMAND (USING REAL FUNCTION) +++
@app.command(name="trade-flow-monitor")
def trade_flow_monitor(
    commodity_code: str = typer.Argument(
        ..., help="The HS commodity code (e.g., '270900' for petroleum)."
    ),
    country_code: str = typer.Argument(
        "842", help="The UN M49 country code (e.g., '842' for USA, '156' for China)."
    ),
):
    """
    Monitors trade flows for a commodity to find anomalies.
    """
    ecoint = EcoInt()
    results = ecoint.monitor_trade_flows(commodity_code, country_code)

    if results.get("error"):
        console.print(f"[bold red]Error:[/bold red] {results['error']}")
        raise typer.Exit(code=1)

    anomalies = results.get("anomalies_detected", [])
    if not anomalies:
        console.print(
            f"[green]No significant anomalies (Z-score > 2.0) detected for HS:{commodity_code} in {country_code}.[/green]"
        )
        console.print(f"Latest Analysis: {results.get('analysis')}")
        return

    table = Table(
        title=f"Trade Flow Anomalies Detected for HS:{commodity_code} in {country_code}"
    )
    table.add_column("Period", style="cyan")
    table.add_column("Value (USD)", style="white")
    table.add_column("Z-Score (Std Devs)", style="magenta")
    table.add_column("Baseline Mean (USD)", style="yellow")

    for a in anomalies:
        table.add_row(
            str(a["period"]),
            f"${a['value_usd']:,.0f}",
            f"{a['z_score']:.2f}",
            f"${a['baseline_mean']:,.0f}",
        )
    console.print(table)


if __name__ == "__main__":
    app()