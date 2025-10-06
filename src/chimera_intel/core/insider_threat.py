"""
Insider Threat & Counterintelligence Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import pandas as pd
import os
from rich.console import Console

console = Console()

# Create a new Typer application for Insider Threat commands

insider_threat_app = typer.Typer(
    name="insider",
    help="Insider Threat & Counterintelligence Analysis",
)


def analyze_log_anomalies(df: pd.DataFrame) -> list:
    """
    Analyzes a DataFrame of log data to find anomalies.
    """
    anomalies = []

    # Anomaly 1: Logins outside of standard business hours (e.g., 8 AM to 6 PM)

    df["hour"] = df["timestamp"].dt.hour
    outside_hours = df[(df["hour"] < 8) | (df["hour"] > 18)]
    for index, row in outside_hours.iterrows():
        anomalies.append(
            f"[bold yellow]Unusual Login Time[/bold yellow]: User '{row['user']}' logged in at {row['timestamp']} from {row['ip_address']}"
        )
    # Anomaly 2: User logging in from multiple locations in a short time frame

    for user in df["user"].unique():
        user_logins = df[df["user"] == user].sort_values("timestamp")
        locations = user_logins["ip_address"].unique()
        if len(locations) > 1:
            # This is a simplified check; a real implementation would check time deltas

            anomalies.append(
                f"[bold red]Multiple Locations[/bold red]: User '{user}' logged in from multiple IPs: {', '.join(locations)}"
            )
    return anomalies


@insider_threat_app.command(
    name="analyze-vpn-logs", help="Analyze VPN logs for insider threat indicators."
)
def analyze_vpn_logs(
    log_file: Annotated[
        str,
        typer.Argument(help="Path to the VPN log file (CSV format)."),
    ],
    flag_anomalies: Annotated[
        bool,
        typer.Option(
            "--flag-anomalies",
            "-f",
            help="Flag anomalous activities based on statistical analysis.",
        ),
    ] = False,
):
    """
    Ingests and analyzes logs from internal systems to identify potential
    insider threats and flag anomalous user behavior.
    """
    console.print(f"Analyzing VPN logs from: {log_file}")

    if not os.path.exists(log_file):
        console.print(f"[bold red]Error:[/bold red] Log file not found at '{log_file}'")
        raise typer.Exit(code=1)
    try:
        # Load the log file into a pandas DataFrame
        # Assuming CSV format: timestamp,user,ip_address,action

        df = pd.read_csv(log_file, parse_dates=["timestamp"])

        if flag_anomalies:
            anomalies = analyze_log_anomalies(df)
            if anomalies:
                console.print(
                    "\n--- [bold red]Potential Insider Threat Anomalies Detected[/bold red] ---"
                )
                for anomaly in anomalies:
                    console.print(f"- {anomaly}")
                console.print("----------------------------------------------------")
            else:
                console.print(
                    "\n[bold green]No obvious anomalies detected.[/bold green]"
                )
        else:
            console.print(
                "\nLog file parsed successfully. Use --flag-anomalies to run analysis."
            )
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during log analysis:[/bold red] {e}"
        )
        raise typer.Exit(code=1)


if __name__ == "__main__":
    insider_threat_app()
