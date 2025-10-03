"""
Deeper Social Media Profile Analysis (SOCMINT) Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import tweepy
from rich.console import Console
from rich.panel import Panel
from collections import Counter

from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.ai_core import (
    perform_sentiment_analysis,
    perform_generative_task,
)

console = Console()

profile_analyzer_app = typer.Typer(
    name="profile-analysis",
    help="Performs deep analysis of a specific social media profile.",
)


def get_user_tweets(username: str, limit: int = 50) -> list:
    """Fetches the most recent tweets for a given username."""
    bearer_token = API_KEYS.twitter_bearer_token
    if not bearer_token:
        raise ValueError("TWITTER_BEARER_TOKEN not found in .env file.")
    client = tweepy.Client(bearer_token)
    user = client.get_user(username=username).data
    if not user:
        raise ValueError(f"User '{username}' not found.")
    response = client.get_users_tweets(
        user.id, max_results=limit, tweet_fields=["entities"]
    )
    return response.data or []


@profile_analyzer_app.command(
    "run",
    help="Create a behavioral and network profile of an individual from their public social media.",
)
def run_profile_analysis(
    username: Annotated[
        str, typer.Argument(help="The username of the profile to analyze.")
    ],
    platform: Annotated[
        str,
        typer.Option(
            "--platform", "-p", help="The social media platform (e.g., twitter)."
        ),
    ] = "twitter",
):
    """
    Analyzes a specific person's public social media profile to understand
    their interests, network, sentiment, and key discussion topics.
    """
    console.print(
        f"Running deep profile analysis for [bold cyan]@{username}[/bold cyan] on {platform}..."
    )

    try:
        if platform.lower() != "twitter":
            console.print(
                f"[bold red]Error:[/bold red] Platform '{platform}' is not currently supported."
            )
            raise typer.Exit(code=1)
        # 1. Scrape user's recent posts

        tweets = get_user_tweets(username)
        if not tweets:
            console.print(f"No recent tweets found for user @{username}.")
            raise typer.Exit()
        console.print(f"Fetched {len(tweets)} recent tweets.")

        # 2. Analyze sentiment, mentions, and hashtags

        sentiments = []
        mentions = Counter()
        hashtags = Counter()
        all_tweets_text = ""

        for tweet in tweets:
            sentiments.append(perform_sentiment_analysis(tweet.text))
            all_tweets_text += tweet.text + "\n\n"
            if tweet.entities:
                for mention in tweet.entities.get("mentions", []):
                    mentions[mention["username"]] += 1
                for hashtag in tweet.entities.get("hashtags", []):
                    hashtags[hashtag["tag"]] += 1
        # 3. Use AI core to summarize themes

        summary_prompt = f"Based on the following tweets from the user @{username}, provide a concise summary of the key themes, topics, and interests they frequently discuss:\n\n{all_tweets_text}"
        summary = perform_generative_task(summary_prompt)

        # 4. Display results

        console.print(
            Panel(
                summary,
                title="[bold green]AI Summary of Key Themes[/bold green]",
                border_style="green",
            )
        )

        sentiment_summary = ", ".join(
            f"{s.capitalize()}: {sentiments.count(s)}" for s in set(sentiments)
        )
        console.print(
            Panel(
                f"Overall Sentiment Distribution: {sentiment_summary}",
                title="[bold blue]Sentiment Analysis[/bold blue]",
                border_style="blue",
            )
        )

        top_mentions = "\n".join(
            [f"- @{user} ({count} times)" for user, count in mentions.most_common(5)]
        )
        console.print(
            Panel(
                top_mentions,
                title="[bold magenta]Top 5 Mentions[/bold magenta]",
                border_style="magenta",
            )
        )

        top_hashtags = "\n".join(
            [f"- #{tag} ({count} times)" for tag, count in hashtags.most_common(5)]
        )
        console.print(
            Panel(
                top_hashtags,
                title="[bold yellow]Top 5 Hashtags[/bold yellow]",
                border_style="yellow",
            )
        )
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1)
