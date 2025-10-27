import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from . import analytics
from .config_loader import API_KEYS  # To get DB params
import psycopg2
import pandas as pd
import matplotlib.pyplot as plt
from typing_extensions import Annotated
from typing import Optional # FIX: Import Optional

# FIX: Removed global console object
# console = Console()
analytics_app = typer.Typer(
    help="Tools for negotiation analytics and decision support."
)


@analytics_app.command("show")
def show_analytics():
    """
    Displays a dashboard with KPIs for negotiation performance.
    """
    # FIX: Instantiate Console inside the function
    console = Console()

    db_params = {
        "dbname": getattr(API_KEYS, "db_name", None),
        "user": getattr(API_KEYS, "db_user", None),
        "password": getattr(API_KEYS, "db_password", None),
        "host": getattr(API_KEYS, "db_host", None),
    }

    if not all(db_params.values()):
        console.print(
            "[bold red]Database configuration is missing. Please check your .env file.[/bold red]"
        )
        return
    kpis = analytics.get_negotiation_kpis(db_params)

    if not kpis:
        console.print("[bold yellow]Could not retrieve any KPI data.[/bold yellow]")
        return
    # --- Create Dashboard ---

    console.print(
        Panel("[bold cyan]Negotiation Performance Dashboard[/bold cyan]", expand=False)
    )

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="dim", width=30)
    table.add_column("Value")

    table.add_row("Total Negotiation Sessions", str(kpis.get("total_sessions", "N/A")))
    table.add_row("Successful Deals", str(kpis.get("successful_deals", "N/A")))

    success_rate = 0
    if kpis.get("total_sessions", 0) > 0:
        success_rate = (
            kpis.get("successful_deals", 0) / kpis.get("total_sessions")
        ) * 100
    table.add_row("Success Rate", f"{success_rate:.2f}%")

    table.add_row(
        "Average Duration", f"{kpis.get('average_duration_hours', 'N/A')} hours"
    )

    console.print(table)

    # --- Optional: Display a simple sentiment trend ---

    if kpis.get("sentiment_trend"):
        console.print("\n[bold]Recent Sentiment Trend (Tone Score):[/bold]")
        for timestamp, score in kpis["sentiment_trend"][-10:]:  # Show last 10
            color = "green" if score > 0.1 else "red" if score < -0.1 else "yellow"
            console.print(f"  - {timestamp}: [bold {color}]{score:.2f}[/bold {color}]")


# --- FIX: Added missing plot-sentiment command ---
@analytics_app.command("plot-sentiment")
def plot_sentiment_trajectory(
    negotiation_id: Annotated[str, typer.Argument(help="The ID of the negotiation to plot.")],
    # FIX: Changed type hint to Optional[str]
    output: Annotated[Optional[str], typer.Option(help="Path to save the plot image file.")] = None,
):
    """
    Plots the sentiment trajectory over time for a negotiation.
    """
    console = Console()
    db_params = {
        "dbname": getattr(API_KEYS, "db_name", None),
        "user": getattr(API_KEYS, "db_user", None),
        "password": getattr(API_KEYS, "db_password", None),
        "host": getattr(API_KEYS, "db_host", None),
    }

    if not all(db_params.values()):
         console.print("Error: Database connection parameters are missing.", style="red")
         return

    try:
        conn = psycopg2.connect(**db_params)
        if conn is None:
            console.print("Error: Could not connect to the database.", style="red")
            return

        # FIX: Changed query to use named-style placeholder
        query = "SELECT timestamp, sentiment FROM messages WHERE negotiation_id = %(neg_id)s ORDER BY timestamp"
        
        # FIX: Changed params to a dictionary to match query and satisfy mypy
        df = pd.read_sql_query(query, conn, params={"neg_id": negotiation_id})
        conn.close()

        if df.empty:
            console.print(f"No messages found for negotiation ID: {negotiation_id}", style="yellow")
            return

        # Ensure 'sentiment' column is numeric, coercing errors
        df['sentiment'] = pd.to_numeric(df['sentiment'], errors='coerce')
        # Drop rows where sentiment could not be converted
        df.dropna(subset=['sentiment'], inplace=True)

        # Convert timestamp to datetime objects if they are not already
        df['timestamp'] = pd.to_datetime(df['timestamp'])


        if df.empty:
             console.print(f"No valid numeric sentiment data found for negotiation ID: {negotiation_id} after cleaning.", style="yellow")
             return

        plt.figure(figsize=(10, 6))
        plt.plot(df["timestamp"], df["sentiment"], marker="o", linestyle="-")
        plt.title(f"Sentiment Trajectory for {negotiation_id}")
        plt.xlabel("Time")
        plt.ylabel("Sentiment Score")
        plt.grid(True)
        plt.xticks(rotation=45) # Rotate x-axis labels for better readability
        plt.tight_layout() # Adjust layout


        if output:
            plt.savefig(output)
            console.print(f"Plot saved to {output}", style="green")
        else:
            plt.show()

    except Exception as e:
        console.print(f"An error occurred: {e}", style="red")
# --- End Fix ---


if __name__ == "__main__":
    analytics_app()