import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from . import analytics
from .config_loader import API_KEYS  # To get DB params

console = Console()
analytics_app = typer.Typer(
    help="Tools for negotiation analytics and decision support."
)


@analytics_app.command("show")
def show_analytics():
    """
    Displays a dashboard with KPIs for negotiation performance.
    """
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


if __name__ == "__main__":
    analytics_app()
