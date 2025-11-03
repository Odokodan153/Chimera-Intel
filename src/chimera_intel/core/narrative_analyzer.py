"""
Disinformation & Narrative Tracking Module for Chimera Intel.
"""

import typer
import httpx
import tweepy
from rich.console import Console
from rich.table import Table
from typing import List, Dict, Any
from rich.panel import Panel
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.http_client import sync_client
from chimera_intel.core.ai_core import analyze_sentiment, generate_swot_from_data

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
    # --- FIX: Changed from Annotated/prompt to standard required Option ---
    query: str = typer.Option(
        ...,
        "--track",
        "-t",
        help="The keyword or phrase to track.",
    ),
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

        # FIX: The function must return the result when called as a module utility.
        return analyzed_content

    except ValueError as e:
        console.print(f"[bold red]Configuration Error:[/bold red] {e}")
        # FIX: Use typer.Exit(code=1)
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")
        # FIX: Use typer.Exit(code=1)
        raise typer.Exit(code=1)

    # --- FIX: Removed the unconditional typer.Exit(code=0) as it stops execution
    # when the function is called as a module utility.
    # raise typer.Exit(code=0)

@narrative_analyzer_app.command(
    name="map", help="Analyze narrative data to map influence operations."
)
def map_influence(
    query: str = typer.Option(
        ...,
        "--track",
        "-t",
        help="The keyword or phrase to analyze for influence operations.",
    ),
):
    """
    Analyzes data from 'track_narrative' to detect how public opinion
    or corporate messaging is being shaped (info ops).
    """
    console.print(
        f"Mapping influence and information operations for: '[bold cyan]{query}[/bold cyan]'"
    )

    try:
        # 1. Reuse existing function to gather data
        console.print("  [grey50]Step 1: Gathering source data...[/grey50]")
        # Note: This will print the table from track_narrative first
        tracking_results = track_narrative(query)

        if not tracking_results:
            console.print(
                "[yellow]No tracking results found. Cannot map influence.[/yellow]"
            )
            raise typer.Exit()

        console.print("\n  [grey50]Step 2: Analyzing gathered data for influence patterns...[/grey50]")

        # 2. Check for AI key
        ai_api_key = API_KEYS.google_api_key
        if not ai_api_key:
            console.print(
                "[bold red]Error:[/bold red] GOOGLE_API_KEY is not set. Cannot perform AI-powered analysis."
            )
            raise typer.Exit(code=1)

        # 3. Prepare data and prompt for AI analysis
        content_summary = "\n".join(
            [
                f"- (Type: {item['type']}, Source: {item['source']}, Sentiment: {item['sentiment']}): {item['content']}"
                for item in tracking_results
            ]
        )

        prompt = (
            "You are an expert information operations (IO) and public opinion analyst. "
            "Your task is to analyze a collection of news articles and social media posts about a specific topic to map influence campaigns. "
            "Based on the following data, generate a report that includes:\n"
            "1. **Key Narratives:** What are the 1-3 dominant narratives being pushed?\n"
            "2. **Key Influencers/Sources:** Which sources or authors appear most frequently or drive the narrative?\n"
            "3. **Sentiment Skew:** Is there a strong positive or negative skew? Does it seem natural or manufactured?\n"
            "4. **Signs of Inauthentic Shaping:** Look for repetition, bot-like language, or coordinated messaging across disparate sources. Are there signs of an active 'info op'?\n"
            "5. **Inferred Objective:** What is the likely goal of the observed narrative shaping (e.g., 'to discredit a product', 'to promote a political figure', 'to shape corporate image')?\n\n"
            f"**Topic:** {query}\n"
            f"**Collected Data:**\n{content_summary}"
        )

        # 4. Call AI for the advanced analysis
        ai_result = generate_swot_from_data(prompt, ai_api_key)
        if ai_result.error:
            console.print(f"[bold red]AI Error:[/bold red] {ai_result.error}")
            raise typer.Exit(code=1)

        influence_report = ai_result.analysis_text

        console.print(
            Panel(
                influence_report,
                title="[bold green]Narrative Influence Map[/bold green]",
                border_style="green",
            )
        )

    except typer.Exit:
        # Catch the exit from the underlying track_narrative call if it fails
        pass
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during influence mapping:[/bold red] {e}"
        )
        raise typer.Exit(code=1)
    
if __name__ == "__main__":
    narrative_analyzer_app()
