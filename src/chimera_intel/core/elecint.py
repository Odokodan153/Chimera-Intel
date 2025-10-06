import typer
import os
import requests
from rich.console import Console
from rich.table import Table
from textblob import TextBlob
import networkx as nx

# Conditional import for tweepy

try:
    import tweepy
except ImportError:
    tweepy = None
app = typer.Typer(
    no_args_is_help=True, help="Electoral/Political Intelligence (ELECINT) tools."
)
console = Console()


class ElecInt:
    """
    Handles ELECINT tasks such as monitoring campaign finance, analyzing sentiment,
    and tracing disinformation sources.
    """

    def __init__(self):
        self.fec_api_key = os.getenv("FEC_API_KEY")
        self.fec_base_url = "https://api.open.fec.gov/v1"

        # Twitter API credentials from environment variables

        self.twitter_bearer_token = os.getenv("TWITTER_BEARER_TOKEN")
        if self.twitter_bearer_token and tweepy:
            self.twitter_client = tweepy.Client(self.twitter_bearer_token)
        else:
            self.twitter_client = None

    def get_campaign_donations(self, committee_id: str, pages: int = 1) -> list:
        """
        Fetches a list of donations to a specific political campaign committee from the FEC.
        """
        if not self.fec_api_key:
            console.print(
                "[bold yellow]FEC_API_KEY environment variable not set. Cannot fetch campaign finance data.[/bold yellow]"
            )
            return []
        donations = []
        try:
            response = requests.get(
                f"{self.fec_base_url}/committee/{committee_id}/schedules/schedule_a/",
                params={"api_key": self.fec_api_key, "per_page": 100, "page": pages},
            )
            response.raise_for_status()
            data = response.json()

            for result in data.get("results", []):
                donations.append(
                    {
                        "contributor_name": result.get("contributor_name"),
                        "amount": result.get("contribution_receipt_amount"),
                        "date": result.get("contribution_receipt_date"),
                        "city": result.get("contributor_city"),
                        "state": result.get("contributor_state"),
                    }
                )
            return donations
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red]Error fetching FEC data: {e}[/bold red]")
            return []

    def analyze_sentiment_drift(self, keyword: str, tweet_count: int = 100) -> dict:
        """
        Analyzes the sentiment of recent tweets containing a specific keyword.
        """
        if not self.twitter_client:
            console.print(
                "[bold yellow]TWITTER_BEARER_TOKEN not set or tweepy not installed. Cannot analyze sentiment.[/bold yellow]"
            )
            return {}
        try:
            tweets = (
                self.twitter_client.search_recent_tweets(
                    query=keyword, max_results=tweet_count
                ).data
                or []
            )
            sentiments = [TextBlob(tweet.text).sentiment.polarity for tweet in tweets]

            avg_sentiment = sum(sentiments) / len(sentiments) if sentiments else 0

            return {
                "keyword": keyword,
                "tweets_analyzed": len(tweets),
                "average_sentiment_polarity": f"{avg_sentiment:.3f}",  # Ranges from -1 (negative) to 1 (positive)
            }
        except Exception as e:
            console.print(f"[bold red]Error fetching tweets: {e}[/bold red]")
            return {}

    def trace_disinformation_source(self, keyword: str, tweet_count: int = 100) -> dict:
        """
        Creates a network graph of retweets to identify key amplifiers of a narrative.
        """
        if not self.twitter_client:
            console.print(
                "[bold yellow]TWITTER_BEARER_TOKEN not set or tweepy not installed. Cannot trace sources.[/bold yellow]"
            )
            return {}
        try:
            tweets = (
                self.twitter_client.search_recent_tweets(
                    query=f'"{keyword}" is:retweet',
                    max_results=tweet_count,
                    expansions=["author_id", "in_reply_to_user_id"],
                ).data
                or []
            )

            graph: nx.DiGraph = nx.DiGraph()
            for tweet in tweets:
                if tweet.in_reply_to_user_id:
                    graph.add_edge(tweet.author_id, tweet.in_reply_to_user_id)
            # Find the most influential nodes (potential amplifiers)

            centrality = nx.degree_centrality(graph)
            top_amplifiers = sorted(
                centrality.items(), key=lambda item: item[1], reverse=True
            )[:5]

            return {
                "keyword": keyword,
                "retweets_analyzed": len(tweets),
                "top_amplifiers_by_centrality": {
                    f"User ID {uid}": score for uid, score in top_amplifiers
                },
            }
        except Exception as e:
            console.print(f"[bold red]Error building network graph: {e}[/bold red]")
            return {}


@app.command(name="campaign-finance")
def campaign_finance(
    committee_id: str = typer.Argument(
        ..., help="FEC committee ID (e.g., C00431445 for Joe Biden's campaign)."
    )
):
    """Fetches and displays campaign donations from the FEC."""
    elecint = ElecInt()
    donations = elecint.get_campaign_donations(committee_id)
    if donations:
        table = Table(title=f"Recent Donations to Committee {committee_id}")
        table.add_column("Contributor", style="cyan")
        table.add_column("Amount (USD)", style="green")
        table.add_column("Date", style="yellow")
        for d in donations[:20]:  # Display first 20
            table.add_row(d["contributor_name"], f"{d['amount']:.2f}", d["date"])
        console.print(table)


@app.command(name="sentiment-drift")
def sentiment_drift(
    keyword: str = typer.Argument(
        ..., help="The political keyword or hashtag to analyze."
    )
):
    """Analyzes public sentiment drift for a political keyword on Twitter."""
    elecint = ElecInt()
    result = elecint.analyze_sentiment_drift(keyword)
    if result:
        console.print_json(data=result)


@app.command(name="trace-source")
def trace_source(
    keyword: str = typer.Argument(
        ..., help="The keyword or phrase to trace through retweets."
    )
):
    """Traces the source of a narrative by analyzing retweet networks."""
    elecint = ElecInt()
    result = elecint.trace_disinformation_source(keyword)
    if result:
        console.print_json(data=result)


if __name__ == "__main__":
    app()