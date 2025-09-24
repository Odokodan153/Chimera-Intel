"""
Module for real-time social media monitoring.

This module provides the functionality to connect to social media APIs (starting with Twitter/X)
and monitor for keywords, hashtags, or user mentions in real-time.
"""

import typer
import tweepy  # type: ignore
import logging
from typing import List, Optional

from .schemas import Tweet, RealTimeMonitoringResult
from .config_loader import API_KEYS
from .utils import console

logger = logging.getLogger(__name__)

# --- Twitter/X Streaming Client ---


class ChimeraTweetStream(tweepy.StreamingClient):
    """
    A custom streaming client to process incoming tweets in real-time.
    """

    def __init__(self, bearer_token, limit=10):
        super().__init__(bearer_token)
        self.tweets: List[Tweet] = []
        self.limit = limit

    def on_tweet(self, tweet):
        """
        This method is called when a new tweet is received from the stream.
        """
        if len(self.tweets) < self.limit:
            parsed_tweet = Tweet(
                id=str(tweet.id),
                text=tweet.text,
                author_id=str(tweet.author_id),
                created_at=str(tweet.created_at),
            )
            self.tweets.append(parsed_tweet)
            console.print(f"[green]Tweet from @{tweet.author_id}:[/green] {tweet.text}")
        else:
            self.disconnect()

    def on_error(self, status_code):
        """
        Handles errors that occur during the streaming session.
        """
        logger.error(f"An error occurred with the Twitter stream: {status_code}")
        return False  # Disconnect on error


def monitor_twitter_stream(keywords: List[str], limit: int) -> RealTimeMonitoringResult:
    """
    Connects to the Twitter/X filtered stream API and monitors for keywords.

    Args:
        keywords (List[str]): A list of keywords or hashtags to monitor.
        limit (int): The number of tweets to collect before stopping.

    Returns:
        RealTimeMonitoringResult: A Pydantic model containing the collected tweets.
    """
    bearer_token = API_KEYS.twitter_bearer_token
    if not bearer_token:
        return RealTimeMonitoringResult(
            query=" ".join(keywords),
            error="Twitter Bearer Token not found in .env file.",
        )
    logger.info(f"Starting real-time Twitter monitoring for keywords: {keywords}")

    stream = ChimeraTweetStream(bearer_token, limit=limit)

    # Clear any existing rules

    rules = stream.get_rules().data
    if rules:
        stream.delete_rules([rule.id for rule in rules])
    # Add new rules for the keywords

    for keyword in keywords:
        stream.add_rules(tweepy.StreamRule(value=keyword))
    try:
        with console.status(
            "[bold cyan]Monitoring Twitter stream in real-time...[/bold cyan]"
        ):
            stream.filter()
    except Exception as e:
        logger.error(f"An unexpected error occurred during the Twitter stream: {e}")
        return RealTimeMonitoringResult(
            query=" ".join(keywords),
            error=f"An unexpected error occurred: {e}",
        )
    return RealTimeMonitoringResult(
        query=" ".join(keywords),
        total_tweets_found=len(stream.tweets),
        tweets=stream.tweets,
    )


# --- Typer CLI Application ---


social_media_monitor_app = typer.Typer()


@social_media_monitor_app.command("run")
def run_real_time_monitoring(
    keywords: List[str] = typer.Argument(..., help="Keywords or hashtags to monitor."),
    limit: int = typer.Option(10, "--limit", "-l", help="Number of tweets to collect."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Monitors Twitter/X in real-time for specific keywords or hashtags.
    """
    from .utils import save_or_print_results
    from .database import save_scan_to_db

    results_model = monitor_twitter_stream(keywords, limit)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=" ".join(keywords), module="social_media_monitor", data=results_dict
    )
