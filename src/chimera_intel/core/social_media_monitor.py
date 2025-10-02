"""
Module for real-time, live monitoring of various social media platforms.
"""

import typer
import tweepy  # type: ignore
from typing import List, Optional
from googleapiclient.discovery import build  # type: ignore
from chimera_intel.core.schemas import (
    TwitterMonitoringResult,
    Tweet,
    YouTubeMonitoringResult,
    YouTubeVideo,
)
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.database import save_scan_to_db

social_media_app = typer.Typer()


class TwitterStreamListener(tweepy.StreamingClient):
    """A listener class for handling incoming tweets from the Twitter stream."""

    def __init__(self, bearer_token: str, limit: int = 10):
        super().__init__(bearer_token)
        self.tweets: List[Tweet] = []
        self.limit = limit

    def on_tweet(self, tweet: tweepy.Tweet) -> None:
        """This function is called when a new tweet is found."""
        self.tweets.append(
            Tweet(
                id=str(tweet.id),
                text=tweet.text,
                author_id=str(tweet.author_id),
                created_at=str(tweet.created_at),
            )
        )
        console.print(
            f"[green]Tweet Found:[/] [cyan]@{tweet.author_id}[/]: {tweet.text}"
        )
        if len(self.tweets) >= self.limit:
            self.disconnect()

    def on_errors(self, errors: dict) -> None:
        console.print(f"[bold red]Twitter Stream Error:[/] {errors}")
        self.disconnect()


def monitor_twitter_stream(keywords: List[str], limit: int) -> TwitterMonitoringResult:
    """Monitors the Twitter stream for a given set of keywords."""
    bearer_token = API_KEYS.twitter_bearer_token
    if not bearer_token:
        return TwitterMonitoringResult(
            query=", ".join(keywords),
            error="Twitter Bearer Token not found in .env file.",
        )
    stream = TwitterStreamListener(bearer_token, limit=limit)

    existing_rules = stream.get_rules().data or []
    if existing_rules:
        stream.delete_rules([rule.id for rule in existing_rules])
    for keyword in keywords:
        stream.add_rules(tweepy.StreamRule(keyword))
    console.print(f"[cyan]Monitoring Twitter for keywords: {keywords}[/]")
    try:
        stream.filter(
            expansions=["author_id"], tweet_fields=["created_at", "author_id"]
        )
    except Exception as e:
        return TwitterMonitoringResult(
            query=", ".join(keywords), error=f"An error occurred: {e}"
        )
    return TwitterMonitoringResult(
        query=", ".join(keywords),
        total_tweets_found=len(stream.tweets),
        tweets=stream.tweets,
    )


def monitor_youtube(query: str, limit: int) -> YouTubeMonitoringResult:
    """Monitors YouTube for new videos matching a query."""
    api_key = API_KEYS.youtube_api_key
    if not api_key:
        return YouTubeMonitoringResult(
            query=query, error="YouTube API key not found in .env file."
        )
    try:
        youtube = build("youtube", "v3", developerKey=api_key)
        request = youtube.search().list(
            q=query, part="snippet", type="video", order="date", maxResults=limit
        )
        response = request.execute()

        videos = []
        for item in response.get("items", []):
            snippet = item.get("snippet", {})
            videos.append(
                YouTubeVideo(
                    id=item.get("id", {}).get("videoId"),
                    title=snippet.get("title"),
                    channel_id=snippet.get("channelId"),
                    channel_title=snippet.get("channelTitle"),
                    published_at=snippet.get("publishedAt"),
                )
            )
        return YouTubeMonitoringResult(
            query=query, total_videos_found=len(videos), videos=videos
        )
    except Exception as e:
        return YouTubeMonitoringResult(
            query=query, error=f"An error occurred with the YouTube API: {e}"
        )


@social_media_app.command("twitter")
def run_twitter_monitoring(
    keywords: List[str] = typer.Argument(..., help="Keywords to monitor."),
    limit: int = typer.Option(10, help="Number of tweets to capture before stopping."),
    output_file: Optional[str] = typer.Option(
        None, help="Save results to a JSON file."
    ),
):
    """Monitors Twitter in real-time for specific keywords."""
    results_model = monitor_twitter_stream(keywords, limit)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=", ".join(keywords),
        module="social_media_monitor_twitter",
        data=results_dict,
    )


@social_media_app.command("youtube")
def run_youtube_monitoring(
    query: str = typer.Argument(..., help="Search query for new videos."),
    limit: int = typer.Option(10, help="Number of recent videos to retrieve."),
    output_file: Optional[str] = typer.Option(
        None, help="Save results to a JSON file."
    ),
):
    """Monitors YouTube for new videos matching a query."""
    results_model = monitor_youtube(query, limit)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=query, module="social_media_monitor_youtube", data=results_dict
    )
