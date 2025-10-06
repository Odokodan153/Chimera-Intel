import typer
from rich.console import Console
from collections import Counter
from Wappalyzer import Wappalyzer, WebPage
from app_store_scraper import AppStore
from textblob import TextBlob

app = typer.Typer(no_args_is_help=True, help="Product Intelligence (PRODINT) tools.")
console = Console()


class ProdInt:
    """
    Handles PRODINT tasks using live data for digital teardowns, adoption/churn analysis,
    and identifying feature gaps.
    """

    def digital_teardown(self, url: str) -> dict:
        """
        Performs a digital teardown of a website to identify its technology stack using Wappalyzer.
        """
        try:
            # Wappalyzer requires a live webpage to analyze

            webpage = WebPage.new_from_url(url)
            wappalyzer = Wappalyzer.latest()
            tech_stack = wappalyzer.analyze_with_versions(webpage)
            return tech_stack
        except Exception as e:
            console.print(f"[bold red]Error during technology analysis: {e}[/bold red]")
            return {}

    def analyze_churn_risk(
        self, app_id: str, country: str = "us", review_count: int = 100
    ) -> dict:
        """
        Analyzes app store reviews to gauge sentiment and estimate churn risk.
        """
        try:
            app = AppStore(country=country, app_name=app_id)
            app.review(how_many=review_count)
            reviews = app.reviews

            if not reviews:
                console.print("[yellow]No reviews found for this app ID.[/yellow]")
                return {}
            sentiments = []
            for review in reviews:
                analysis = TextBlob(review["review"])
                if analysis.sentiment.polarity > 0.1:
                    sentiments.append("positive")
                elif analysis.sentiment.polarity < -0.1:
                    sentiments.append("negative")
                else:
                    sentiments.append("neutral")
            sentiment_counts = Counter(sentiments)
            total_reviews = len(reviews)

            positive_pct = (sentiment_counts.get("positive", 0) / total_reviews) * 100
            negative_pct = (sentiment_counts.get("negative", 0) / total_reviews) * 100

            churn_risk = "Low"
            if negative_pct > 35:
                churn_risk = "High"
            elif negative_pct > 15:
                churn_risk = "Medium"
            return {
                "app_id": app_id,
                "reviews_analyzed": total_reviews,
                "positive_sentiment": f"{positive_pct:.1f}%",
                "negative_sentiment": f"{negative_pct:.1f}%",
                "estimated_churn_risk": churn_risk,
            }
        except Exception as e:
            console.print(
                f"[bold red]Error fetching or analyzing app reviews: {e}[/bold red]"
            )
            return {}

    def find_feature_gaps(
        self, our_features: list, competitor_features: list, requested_features: list
    ) -> dict:
        """
        Identifies feature gaps by comparing our product, a competitor's product, and user requests.
        This function remains as an internal analysis tool, as it relies on curated data.
        """
        our_set = set(our_features)
        competitor_set = set(competitor_features)
        requested_set = set(requested_features)

        gaps_we_have = (competitor_set - our_set) & requested_set
        gaps_competitor_has = (our_set - competitor_set) & requested_set
        unaddressed_requests = requested_set - our_set - competitor_set

        return {
            "our_advantages": list(gaps_competitor_has),
            "competitor_advantages": list(gaps_we_have),
            "unaddressed_market_needs": list(unaddressed_requests),
        }


@app.command(name="teardown")
def teardown(
    url: str = typer.Argument(
        ...,
        help="The full URL (e.g., https://www.example.com) of the product website to analyze.",
    )
):
    """Performs a digital teardown to identify a website's technology stack."""
    prodint = ProdInt()
    tech = prodint.digital_teardown(url)
    if tech:
        console.print(f"[bold green]Technology Stack for {url}:[/bold green]")
        console.print_json(data=tech)


@app.command(name="churn-analysis")
def churn_analysis(
    app_id: str = typer.Argument(
        ..., help="The app ID from the Google Play Store (e.g., com.google.android.gm)."
    ),
    country: str = typer.Option(
        "us", "--country", "-c", help="The two-letter country code for the App Store."
    ),
    reviews: int = typer.Option(
        200, "--reviews", "-r", help="Number of recent reviews to analyze."
    ),
):
    """Analyzes Google Play Store reviews to estimate churn risk."""
    prodint = ProdInt()
    data = prodint.analyze_churn_risk(app_id, country, reviews)
    if data:
        console.print(
            f"[bold green]Churn & Sentiment Analysis for {app_id}:[/bold green]"
        )
        console.print_json(data=data)


@app.command(name="feature-gaps")
def feature_gaps():
    """Identifies feature gaps between our product, a competitor, and user requests."""
    # This remains a user-driven command, as the data is internal/curated.

    our_features = ["Dashboard", "User Login", "Reporting", "API Access"]
    competitor_features = ["Dashboard", "User Login", "Reporting", "SSO Integration"]
    requested_features = [
        "SSO Integration",
        "Team Collaboration",
        "Reporting",
        "Mobile App",
    ]

    prodint = ProdInt()
    gaps = prodint.find_feature_gaps(
        our_features, competitor_features, requested_features
    )

    console.print("[bold green]Feature Gap Analysis:[/bold green]")
    console.print_json(data=gaps)


if __name__ == "__main__":
    app()
