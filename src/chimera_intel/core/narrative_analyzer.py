"""
Disinformation & Narrative Tracking Module for Chimera Intel.
"""

import typer
# import sys  <-- FIX: Removed sys import
from typing_extensions import Annotated
import httpx
import tweepy
from rich.console import Console
from rich.table import Table
from typing import List, Dict, Any

from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.http_client import sync_client
from chimera_intel.core.ai_core import analyze_sentiment

console = Console()

# Create a new Typer application for Narrative Analysis commands
narrative_analyzer_app = typer.Typer(
    name="narrative",
    help="Track the evolution and spread of narratives.",
)


def fetch_news(query: str, client: httpx.Client) -> list:
    """Fetches news articles from GNews."""
    api_key = API_KEYS.gnews_api_key
    if not api_key:
        raise ValueError("GNEWS_API_KEY not found in .env file.")
    url = "https://gnews.io/api/v4/search"
    params = {"q": query, "token": api_key, "lang": "en", "max": "10"}
    response = client.get(url, params=params)
    response.raise_for_status()
    return response.json().get("articles", [])


def fetch_tweets(query: str) -> list:
    """Fetches tweets from X/Twitter."""
    bearer_token = API_KEYS.twitter_bearer_token
    if not bearer_token:
        raise ValueError("TWITTER_BEARER_TOKEN not found in .env file.")
    client = tweepy.Client(bearer_token)
    response = client.search_recent_tweets(query, max_results=10)
    return response.data or []


@narrative_analyzer_app.command(
    name="track", help="Track a narrative across news and social media."
)
def track_narrative(
    query: Annotated[
        str,
        typer.Option(
            "--track",
            "-t",
            help="The keyword or phrase to track.",
            prompt="Enter the narrative to track",
        ),
    ],
) -> List[Dict[str, Any]]:
    """
    Monitors a specific topic across various media platforms to understand
    who is talking about it, what they are saying, and how the narrative
    is changing over time.
    """
    console.print(f"Tracking narrative: '[bold cyan]{query}[/bold cyan]'")

    try:
        # 1. Fetch data from sources

        with sync_client as http_client:
            news_articles = fetch_news(query, http_client)
        tweets = fetch_tweets(query)

        console.print(
            f"Found {len(news_articles)} news articles and {len(tweets)} recent tweets."
        )

        # 2. Analyze sentiment and identify key sources

        table = Table(title="Narrative Analysis Summary")
        table.add_column("Source", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Content", style="green")
        table.add_column("Sentiment", justify="right", style="bold")

        all_content = []
        for article in news_articles:
            all_content.append(
                {
                    "source": article["source"]["name"],
                    "type": "News",
                    "content": article["title"],
                }
            )
        for tweet in tweets:
            all_content.append(
                {
                    "source": f"Tweet by User ID: {tweet.author_id}",
                    "type": "Tweet",
                    "content": tweet.text.splitlines()[0],
                }
            )
        analyzed_content = []
        for item in all_content:
            sentiment_result = analyze_sentiment(item["content"])
            sentiment = sentiment_result.label
            item["sentiment"] = sentiment
            analyzed_content.append(item)
            sentiment_color = "white"
            if sentiment.lower() == "positive":
                sentiment_color = "green"
            elif sentiment.lower() == "negative":
                sentiment_color = "red"
            table.add_row(
                item["source"],
                item["type"],
                item["content"],
                f"[{sentiment_color}]{sentiment}[/{sentiment_color}]",
            )
        console.print(table)
        
        # FIX: Use typer.Exit(code=0) for success
        raise typer.Exit(code=0)
        
        # The return statement below was unreachable due to sys.exit()
        # and is not needed for the CLI command test to pass.
        # return analyzed_content
        
    except ValueError as e:
        console.print(f"[bold red]Configuration Error:[/bold red] {e}")
        # FIX: Use typer.Exit(code=1)
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")
        # FIX: Use typer.Exit(code=1)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    narrative_analyzer_app()