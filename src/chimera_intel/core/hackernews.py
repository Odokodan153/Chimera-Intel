import typer
import requests
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True, help="Hacker News (HackerNews) tools.")
console = Console()


class HackerNews:
    """
    Handles HackerNews tasks by fetching and displaying the latest articles
    from the Hacker News API.
    """

    def get_top_stories(self, limit: int = 10) -> list:
        """
        Fetches the top stories from Hacker News.
        """
        try:
            top_stories_url = "https://hacker-news.firebaseio.com/v0/topstories.json"
            top_stories = requests.get(top_stories_url).json()

            articles = []
            for story_id in top_stories[:limit]:
                story_url = (
                    f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"
                )
                story_details = requests.get(story_url).json()
                articles.append(
                    {
                        "title": story_details.get("title"),
                        "author": story_details.get("by"),
                        "published": story_details.get("time"),
                        "link": story_details.get("url"),
                    }
                )
            return articles
        except Exception as e:
            console.print(f"[bold red]Error fetching Hacker News feed: {e}[/bold red]")
            return []


@app.command(name="top")
def top_stories(
    limit: int = typer.Option(
        10, "--limit", "-l", help="Number of recent articles to display."
    )
):
    """Fetches the top stories from Hacker News."""
    hackernews = HackerNews()
    articles = hackernews.get_top_stories(limit)

    if not articles:
        console.print("[yellow]No recent articles found in the feed.[/yellow]")
        return
    table = Table(title="Top Stories from Hacker News")
    table.add_column("Published", style="yellow")
    table.add_column("Title", style="cyan")
    table.add_column("Author", style="magenta")

    for article in articles:
        table.add_row(str(article["published"]), article["title"], article["author"])
    console.print(table)


if __name__ == "__main__":
    app()
