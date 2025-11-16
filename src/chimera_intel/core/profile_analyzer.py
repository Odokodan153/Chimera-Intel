"""
Profile Analyzer for Chimera Intel.

Analyzes social media profiles to build a behavioral and psychographic summary.
"""

import typer
import tweepy
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.panel import Panel
from collections import Counter
from .config_loader import API_KEYS
from .ai_core import generate_swot_from_data

console = Console()
profile_analyzer_app = typer.Typer()


def get_user_timeline(username: str, count: int = 50) -> List[Dict[str, Any]]:
    """Fetches the most recent tweets from a user's timeline."""
    auth = tweepy.OAuth2BearerHandler(API_KEYS.twitter_bearer_token)
    api = tweepy.API(auth)

    try:
        tweets = api.user_timeline(
            screen_name=username, count=count, tweet_mode="extended"
        )
        return [tweet._json for tweet in tweets]
    except tweepy.errors.TweepyException as e:
        console.print(f"[bold red]Twitter API Error:[/bold red] {e}")
        return []


def generate_behavioral_profile(
    username: str, tweets: List[Dict[str, Any]]
) -> Optional[str]:
    """Uses a generative AI model to create a behavioral profile from tweets."""
    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print("[bold red]Error:[/bold red] Google API key not configured.")
        return None
    # Create a summary of the tweets for the prompt

    tweet_summary = "\n".join(
        [f"- {t.get('full_text', '')}" for t in tweets[:10]]
    )  # Use a sample

    prompt = f"""
    As a behavioral psychologist, analyze the following tweets from the user '{username}'.
    Based on their language, topics, and sentiment, create a brief psychographic and behavioral profile.
    Focus on communication style, recurring themes, and potential interests.

    **Recent Tweets:**
    {tweet_summary}
    """

    ai_result = generate_swot_from_data(prompt, api_key)
    if ai_result.error:
        console.print(f"[bold red]AI Analysis Error:[/bold red] {ai_result.error}")
        return None
    return ai_result.analysis_text


@profile_analyzer_app.command("twitter")
def analyze_twitter_profile(
    username: str = typer.Argument(..., help="The Twitter username (without the @)."),
    tweet_count: int = typer.Option(
        50, "--count", "-c", help="Number of recent tweets to analyze."
    ),
):
    """
    Analyzes a Twitter user's profile and recent tweets for behavioral insights.
    """
    console.print(
        f"[bold cyan]Analyzing Twitter profile for @{username}...[/bold cyan]"
    )

    if not API_KEYS.twitter_bearer_token:
        console.print(
            "[bold red]Error:[/bold red] Twitter Bearer Token is not configured."
        )
        raise typer.Exit(code=1)
    tweets = get_user_timeline(username, tweet_count)
    if not tweets:
        console.print("[yellow]No tweets found for this user.[/yellow]")
        return
    # Basic stats

    mentions: Counter = Counter()
    hashtags: Counter = Counter()
    for tweet in tweets:
        if "entities" in tweet:
            for mention in tweet["entities"].get("user_mentions", []):
                mentions[mention["screen_name"]] += 1
            for hashtag in tweet["entities"].get("hashtags", []):
                hashtags[hashtag["text"]] += 1
    console.print(
        Panel(
            f"Most Mentioned: {mentions.most_common(3)}\nMost Used Hashtags: {hashtags.most_common(3)}",
            title="[bold green]Activity Summary[/bold green]",
            border_style="green",
        )
    )

    # AI-powered behavioral profile

    profile = generate_behavioral_profile(username, tweets)
    if profile:
        console.print(
            Panel(
                profile,
                title="[bold blue]AI Behavioral Profile[/bold blue]",
                border_style="blue",
            )
        )
