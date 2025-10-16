"""
Influence & Information Operations (IO) Tracking Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import httpx
from rich.table import Table
import tweepy

from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.utils import console


# Create a new Typer application for IO Tracking commands

io_tracking_app = typer.Typer(
    name="influence",
    help="Influence & Information Operations (IO) Tracking.",
)


def search_news_narrative(narrative: str, client: httpx.Client) -> list:
    """Searches for a narrative in news articles using the GNews API."""
    api_key = API_KEYS.gnews_api_key
    if not api_key:
        raise ValueError("GNEWS_API_KEY not found in .env file.")
    url = "https://gnews.io/api/v4/search"
    params = {"q": f'"{narrative}"', "token": api_key, "lang": "en", "max": "10"}
    response = client.get(url, params=params)
    response.raise_for_status()
    return response.json().get("articles", [])


def search_twitter_narrative(narrative: str) -> list:
    """Searches for a narrative on Twitter."""
    bearer_token = API_KEYS.twitter_bearer_token
    if not bearer_token:
        typer.echo(
            "Warning: TWITTER_BEARER_TOKEN not found. Skipping Twitter search.",
            err=True,
        )
        return []
    try:
        client = tweepy.Client(bearer_token)
        # In a real scenario, handle pagination and more complex queries

        response = client.search_recent_tweets(
            f'"{narrative}" -is:retweet', max_results=20
        )
        return response.data or []
    except Exception as e:
        typer.echo(f"Error searching Twitter: {e}", err=True)
        return []


def search_reddit_narrative(narrative: str, client: httpx.Client) -> list:
    """Searches for a narrative on Reddit."""
    headers = {"User-Agent": "Chimera-Intel IO Tracker v1.0"}
    url = f"https://www.reddit.com/search.json?q={narrative}&sort=new"
    try:
        response = client.get(url, headers=headers)
        response.raise_for_status()
        return response.json().get("data", {}).get("children", [])
    except Exception as e:
        typer.echo(f"Error searching Reddit: {e}", err=True)
        return []


@io_tracking_app.command(
    name="track", help="Track a narrative to identify influence campaigns."
)
def track_influence(
    narrative: Annotated[
        str,
        typer.Option(
            "--narrative",
            "-n",
            help="The narrative or topic to track for influence operations.",
            prompt="Enter the narrative to track",
        ),
    ],
):
    """
    Tracks a narrative across various platforms to identify coordinated
    inauthentic behavior and information operations.
    """
    console.print(
        f"Tracking influence campaign for narrative: '[bold cyan]{narrative}[/bold cyan]'"
    )

    try:
        # We manage the client context here to ensure it's available for all searches

        with httpx.Client() as client:
            news_articles = search_news_narrative(narrative, client)
            search_twitter_narrative(narrative)
            search_reddit_narrative(narrative, client)
        console.print(
            f"\nFound {len(news_articles)} news articles related to the narrative."
        )

        if not news_articles:
            console.print("\nNo significant propagation found in news media.")
            raise typer.Exit()
        table = Table(title="News Narrative Analysis")
        table.add_column("Source", style="cyan")
        table.add_column("Title", style="green")

        for article in news_articles:
            table.add_row(article.get("source", {}).get("name"), article.get("title"))
        console.print(table)
    except ValueError as e:
        typer.echo(f"Configuration Error: {e}", err=True)
        raise typer.Exit(code=1)
    except httpx.HTTPStatusError as e:
        typer.echo(
            f"API Error: Failed to fetch data. Status code: {e.response.status_code}",
            err=True,
        )
        raise typer.Exit(code=1)
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    io_tracking_app()
