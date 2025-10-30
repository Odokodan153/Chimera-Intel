"""
Insider Threat & Counterintelligence Module for Chimera Intel.
"""

import typer
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
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["hour"] = df["timestamp"].dt.hour
    outside_hours = df[(df["hour"] < 8) | (df["hour"] > 18)]
    for index, row in outside_hours.iterrows():
        anomalies.append(
            f"Unusual Login Time: User '{row['user']}' logged in at {row['timestamp']} from {row['ip_address']}"
        )
    # Anomaly 2: User logging in from multiple locations in a short time frame
    for user in df["user"].unique():
        user_logins = df[df["user"] == user].sort_values("timestamp")
        locations = user_logins["ip_address"].unique()
        if len(locations) > 1:
            # This is a simplified check; a real implementation would check time deltas
            anomalies.append(
                f"Multiple Locations: User '{user}' logged in from multiple IPs: {', '.join(locations)}"
            )
    return anomalies


@insider_threat_app.command(
    name="analyze-vpn-logs", help="Analyze VPN logs for insider threat indicators."
)
def analyze_vpn_logs(
    log_file: str = typer.Argument(..., help="Path to the VPN log file (CSV format)."),
    flag_anomalies: bool = typer.Option(
        False,
        "--flag-anomalies",
        "-f",
        help="Flag anomalous activities based on statistical analysis.",
    ),
):
    """
    Ingests and analyzes logs from internal systems to identify potential
    insider threats and flag anomalous user behavior.
    """
    typer.echo(f"Analyzing VPN logs from: {log_file}")

    if not os.path.exists(log_file):
        typer.echo(f"Error: Log file not found at '{log_file}'", err=True)
        raise typer.Exit(code=1)
    try:
        # Load the log file into a pandas DataFrame
        # Assuming CSV format: timestamp,user,ip_address,action
        df = pd.read_csv(log_file)

        if flag_anomalies:
            anomalies = analyze_log_anomalies(df)
            if anomalies:
                typer.echo("\n--- Potential Insider Threat Anomalies Detected ---")
                for anomaly in anomalies:
                    typer.echo(f"- {anomaly}")
                typer.echo("----------------------------------------------------")
            else:
                typer.echo("\nNo obvious anomalies detected.")
        else:
            typer.echo(
                "\nLog file parsed successfully. Use --flag-anomalies to run analysis."
            )
    except Exception as e:
        typer.echo(f"An error occurred during log analysis: {e}", err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    insider_threat_app()
