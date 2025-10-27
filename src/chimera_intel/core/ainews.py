import typer
import feedparser
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    no_args_is_help=True, help="Artificial Intelligence News (AINews) tools."
)
# FIX: Removed global console object.
# console = Console()


class AiNews:
    """
    Handles AINews tasks by fetching and displaying the latest articles
    from technology news sources.
    """

    def get_latest_ai_news(self, limit: int = 10) -> list:
        """
        Fetches the latest AI-related news from the Ars Technica feed.
        """
        # FIX: Instantiate Console inside the function.
        console = Console()
        
        # URL for the Ars Technica feed, which consistently has high-quality AI news
        feed_url = "http://feeds.arstechnica.com/arstechnica/index/"

        try:
            feed = feedparser.parse(feed_url)

            ai_articles = []
            for entry in feed.entries:
                # Filter for articles specifically about AI

                if (
                    "ai" in entry.title.lower()
                    or "artificial intelligence" in entry.title.lower()
                ):
                    ai_articles.append(
                        {
                            "title": entry.title,
                            "author": entry.author,
                            "published": entry.published,
                            "link": entry.link,
                        }
                    )
                if len(ai_articles) >= limit:
                    break
            return ai_articles
        except Exception as e:
            console.print(f"[bold red]Error fetching AI news feed: {e}[/bold red]")
            return []


@app.command(name="latest")
def latest_news(
    limit: int = typer.Option(
        10, "--limit", "-l", help="Number of recent articles to display."
    )
):
    """Fetches the latest AI news from Ars Technica."""
    # FIX: Instantiate Console inside the function.
    console = Console()
    
    ainews = AiNews()
    articles = ainews.get_latest_ai_news(limit)

    if not articles:
        console.print("[yellow]No recent AI articles found in the feed.[/yellow]")
        return
    table = Table(title="Latest AI News from Ars Technica")
    table.add_column("Published", style="yellow")
    table.add_column("Title", style="cyan")
    table.add_column("Author", style="magenta")

    for article in articles:
        # Format the publication date for better readability

        pub_date = article["published"].split("T")[0]
        table.add_row(pub_date, article["title"], article["author"])
    console.print(table)


if __name__ == "__main__":
    app()