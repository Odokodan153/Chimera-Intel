"""
Influence & Information Operations (IO) Tracking Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import httpx
from rich.console import Console
from rich.table import Table
from collections import Counter
import tweepy

from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.http_client import get_http_client

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
    params = {"q": f'"{narrative}"', "token": api_key, "lang": "en", "max": 10}
    response = client.get(url, params=params)
    response.raise_for_status()
    return response.json().get("articles", [])


def search_twitter_narrative(narrative: str) -> list:
    """Searches for a narrative on Twitter."""
    bearer_token = API_KEYS.twitter_bearer_token
    if not bearer_token:
        print(
            "[yellow]Warning: TWITTER_BEARER_TOKEN not found. Skipping Twitter search.[/yellow]"
        )
        return []
    try:
        client = tweepy.Client(bearer_token)
        response = client.search_recent_tweets(
            f'"{narrative}" -is:retweet', max_results=20
        )
        return response.data or []
    except Exception as e:
        print(f"[red]Error searching Twitter: {e}[/red]")
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
        print(f"[red]Error searching Reddit: {e}[/red]")
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
    console = Console()
    console.print(
        f"Tracking influence campaign for narrative: '[bold cyan]{narrative}[/bold cyan]'"
    )

    try:
        with get_http_client() as client:
            # 1. Search for the narrative across multiple platforms

            news_articles = search_news_narrative(narrative, client)
            tweets = search_twitter_narrative(narrative)
            reddit_posts = search_reddit_narrative(narrative, client)

            console.print(
                f"\nFound {len(news_articles)} news articles, {len(tweets)} tweets, and {len(reddit_posts)} Reddit posts."
            )

            # 2. Analyze the results to identify patterns

            if not any([news_articles, tweets, reddit_posts]):
                console.print(
                    "\nNo significant propagation found across monitored platforms."
                )
                raise typer.Exit()
            table = Table(title="Narrative Propagation Analysis")
            table.add_column("Platform", style="cyan")
            table.add_column("Source/Author", style="magenta")
            table.add_column("Content/Title", style="green")

            all_urls = []
            for article in news_articles:
                table.add_row("News", article["source"]["name"], article["title"])
                all_urls.append(article["url"])
            for tweet in tweets:
                table.add_row(
                    "Twitter", f"@{tweet.author_id}", tweet.text.splitlines()[0]
                )
                # Extract URLs from tweet entities

                if tweet.entities and "urls" in tweet.entities:
                    for url_info in tweet.entities["urls"]:
                        all_urls.append(url_info["expanded_url"])
            for post in reddit_posts:
                data = post.get("data", {})
                table.add_row(
                    "Reddit", f"r/{data.get('subreddit')}", data.get("title")
                )
                if "url" in data:
                    all_urls.append(data["url"])
            console.print(table)

            # 3. Identify cross-platform amplification

            url_counts = Counter(all_urls)
            amplified_urls = {
                url: count for url, count in url_counts.items() if count > 1
            }

            if amplified_urls:
                console.print(
                    "\n--- [bold yellow]Cross-Platform Amplification Detected[/bold yellow] ---"
                )
                amplification_table = Table(title="Amplified URLs")
                amplification_table.add_column("URL", style="cyan")
                amplification_table.add_column("Mention Count", style="green")
                for url, count in amplified_urls.items():
                    amplification_table.add_row(url, str(count))
                console.print(amplification_table)
            else:
                console.print(
                    "\nNo significant cross-platform URL amplification detected."
                )
    except ValueError as e:
        print(f"Configuration Error: {e}")
        raise typer.Exit(code=1)
    except httpx.HTTPStatusError as e:
        print(f"API Error: Failed to fetch data. Status code: {e.response.status_code}")
        raise typer.Exit(code=1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    io_tracking_app()
