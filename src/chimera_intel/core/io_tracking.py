"""
Influence & Information Operations (IO) Tracking Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import httpx

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
    params = {"q": narrative, "token": api_key}
    response = client.get(url, params=params)
    response.raise_for_status()
    return response.json().get("articles", [])


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
    print(f"Tracking influence campaign for narrative: '{narrative}'")

    try:
        with get_http_client() as client:
            # 1. Search for the narrative in mainstream and fringe news sources

            articles = search_news_narrative(narrative, client)
            print(f"\nFound {len(articles)} news articles related to the narrative.")

            # In a real implementation, you would add more data sources here,
            # such as social media platforms (X/Twitter, Reddit), forums, etc.

            # 2. Analyze the results to identify patterns

            if articles:
                print("\n--- Initial Narrative Propagation ---")
                for article in articles[:5]:  # Display top 5 results
                    print(
                        f"- Source: {article['source']['name']} | Title: {article['title']}"
                    )
                print("-----------------------------------")
            else:
                print("\nNo significant propagation found in news media yet.")
            # The next steps would involve analyzing the timeline of publications,
            # the sentiment of the articles, and the connections between the sources.
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
