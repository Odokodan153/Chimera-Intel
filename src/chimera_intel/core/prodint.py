"""
Product Intelligence (PRODINT) Module
Handles tasks such as digital teardowns, adoption/churn analysis,
and identifying feature gaps using live data.
"""

import typer
import httpx
import asyncio
import logging
from bs4 import BeautifulSoup
from collections import Counter
from Wappalyzer import Wappalyzer, WebPage
from app_store_scraper import AppStore
from google_play_scraper import search, app
from textblob import TextBlob
from typing import List, Dict, Set
from hashlib import sha256
import re
from datetime import datetime
from chimera_intel.core.http_client import get_async_http_client
from chimera_intel.core.scheduler import add_job
from chimera_intel.core.page_monitor import check_for_changes  
from chimera_intel.core.utils import console

# --- ARG INTEGRATION IMPORTS ---
from chimera_intel.core.arg_service import (
    arg_service_instance,
    BaseEntity,
    Relationship,
)
# --- END ARG INTEGRATION IMPORTS ---

app = typer.Typer(no_args_is_help=True, help="Product Intelligence (PRODINT) tools.")
logger = logging.getLogger(__name__)


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
            webpage = WebPage.new_from_url(url)
            wappalyzer = Wappalyzer()
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
            app_store = AppStore(country=country, app_name=app_id)
            app_store.review(how_many=review_count)
            reviews = app_store.reviews

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

    def monitor_developer_apps(self, developer_name: str, country: str = "us") -> dict:
        """
        Monitors the Google Play Store for apps released by a specific developer.
        """
        try:
            search_results = search(
                query=developer_name,
                page=1,
                country=country,
            )
            
            developer_apps = [
                r for r in search_results if r["developer"] == developer_name
            ]
            
            if not developer_apps:
                return {
                    "developer_name": developer_name,
                    "apps_found": 0,
                    "apps": [],
                }
            
            app_details_list = []
            for app_result in developer_apps:
                app_id = app_result["appId"]
                details = app(app_id, lang="en", country=country)
                app_details_list.append({
                    "app_id": app_id,
                    "title": details["title"],
                    "version": details.get("version", "N/A"),
                    "updated": details.get("updated", "N/A"),
                    "permissions": [p.get("permission") for p in details.get("permissions", []) if p.get("permission")]
                })
            
            return {
                "developer_name": developer_name,
                "apps_found": len(app_details_list),
                "apps": app_details_list,
            }
        except Exception as e:
            console.print(
                f"[bold red]Error searching for developer apps: {e}[/bold red]"
            )
            return {"developer_name": developer_name, "error": str(e)}

    def find_feature_gaps(
        self, our_features: List[str], competitor_features: List[str], requested_features: List[str]
    ) -> dict:
        """
        Identifies feature gaps by comparing our product, a competitor's product, and user requests.
        This function remains as an internal analysis tool, as it relies on curated data.
        """
        # Case-insensitive and whitespace-stripped comparison
        our_set = {f.lower().strip() for f in our_features}
        competitor_set = {f.lower().strip() for f in competitor_features}
        requested_set = {f.lower().strip() for f in requested_features}

        gaps_we_have = (competitor_set - our_set) & requested_set
        gaps_competitor_has = (our_set - competitor_set) & requested_set
        unaddressed_requests = requested_set - our_set - competitor_set

        return {
            "our_advantages_vs_requested": list(gaps_competitor_has),
            "competitor_advantages_vs_requested": list(gaps_we_have),
            "unaddressed_market_needs": list(unaddressed_requests),
            "all_our_features": list(our_set),
            "all_competitor_features": list(competitor_set),
        }

    async def _ingest_features_to_arg(self, url: str, features: List[str]):
        """Helper function to ingest scraped features into the ARG."""
        try:
            entities = []
            relationships = []
            
            page_entity = BaseEntity(
                id_value=url,
                id_type="url",
                label="WebPage",
                properties={"type": "FeaturePage", "last_scraped": datetime.now().isoformat()}
            )
            entities.append(page_entity)

            for feature_text in features:
                feature_entity = BaseEntity(
                    id_value=feature_text.lower(),
                    id_type="name",
                    label="Feature",
                    properties={"name": feature_text}
                )
                entities.append(feature_entity)
                
                rel = Relationship(
                    source=page_entity,
                    target=feature_entity,
                    label="HAS_FEATURE"
                )
                relationships.append(rel)
            
            arg_service_instance.ingest_entities_and_relationships(entities, relationships)
            logger.info(f"Successfully ingested {len(features)} features from {url} into ARG.")
        except Exception as e:
            logger.error(f"Failed to ingest features from {url} into ARG: {e}")

    async def scrape_features_from_page(self, url: str) -> List[str]:
        """
        (Best-effort) Scrapes a list of features from a product or pricing page.
        """
        features: Set[str] = set()
        try:
            async with get_async_http_client() as client:
                response = await client.get(url, follow_redirects=True, timeout=20.0)
                response.raise_for_status()
            
            soup = BeautifulSoup(response.text, "html.parser")
            
            potential_sections = soup.find_all(
                ["div", "section", "ul"], 
                {"class": [re.compile(r"feature"), re.compile(r"pricing"), re.compile(r"plan")]}
            )
            
            if not potential_sections:
                potential_sections = soup.find_all("body")

            for section in potential_sections:
                items = section.find_all("li")
                if not items:
                    items = section.find_all(class_=re.compile(r"feature-item"))

                for item in items:
                    text = item.get_text(strip=True)
                    if text and len(text) > 2 and len(text) < 100 and not text.lower().startswith("sign up"):
                        features.add(text)
            
            feature_list = list(features)
            logger.info(f"Scraped {len(feature_list)} potential features from {url}")

            # --- ARG INGESTION ---
            if feature_list:
                await self._ingest_features_to_arg(url, feature_list)
            # --- END ARG INGESTION ---
            
            return feature_list
        
        except httpx.RequestError as e:
            console.print(f"[bold red]Error scraping features from {url}: {e}[/bold red]")
            return []
        except Exception as e:
            console.print(f"[bold red]An unexpected error occurred during feature scraping: {e}[/bold red]")
            return []

    async def _ingest_catalog_to_arg(self, url: str, products: List[Dict[str, str]]):
        """Helper function to ingest scraped catalog into the ARG."""
        try:
            entities: List[BaseEntity] = []
            relationships: List[Relationship] = []

            catalog_entity = BaseEntity(
                id_value=url,
                id_type="url",
                label="WebPage",
                properties={"type": "ProductCatalog", "last_scraped": datetime.now().isoformat()}
            )
            entities.append(catalog_entity)

            for product in products:
                product_name = product['name']
                # Create a unique ID for the product based on its name and the catalog URL
                product_unique_id = f"{product_name}@{url}" 
                
                product_entity = BaseEntity(
                    id_value=product_unique_id,
                    id_type="product_id",
                    label="Product",
                    properties={"name": product_name, "price_str": product.get("price", "N/A")}
                )
                entities.append(product_entity)

                rel = Relationship(
                    source=catalog_entity,
                    target=product_entity,
                    label="LISTS_PRODUCT"
                )
                relationships.append(rel)

            arg_service_instance.ingest_entities_and_relationships(entities, relationships)
            logger.info(f"Successfully ingested {len(products)} products from {url} into ARG.")
        except Exception as e:
            logger.error(f"Failed to ingest catalog from {url} into ARG: {e}")

    async def scrape_ecommerce_catalog(self, url: str) -> List[Dict[str, str]]:
        """
        (Best-effort) Scrapes product listings from a generic e-commerce catalog page.
        """
        products: List[Dict[str, str]] = []
        try:
            async with get_async_http_client() as client:
                response = await client.get(url, follow_redirects=True, timeout=20.0)
                response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")

            product_cards = soup.find_all("div", class_=[
                re.compile(r"product-card"), 
                re.compile(r"product-item"), 
                re.compile(r"list-item"),
                re.compile(r"product-tile")
            ])
            
            if not product_cards:
                product_cards = soup.find_all("li", class_=re.compile(r"product"))

            for card in product_cards:
                name = card.find(["h2", "h3", "h4", "a"], class_=re.compile(r"title|name|heading"))
                price = card.find("span", class_=re.compile(r"price|amount"))
                
                if not name:
                    name = card.find("a", href=True)
                
                if not price:
                    price = card.find(string=re.compile(r"[$€£]"))

                product_name = name.get_text(strip=True) if name else "N/A"
                product_price = price.get_text(strip=True) if price else "N/A"

                if product_name != "N/A":
                    products.append({"name": product_name, "price": product_price})
            
            logger.info(f"Scraped {len(products)} products from {url}")

            # --- ARG INGESTION ---
            if products:
                await self._ingest_catalog_to_arg(url, products)
            # --- END ARG INGESTION ---

            return products

        except httpx.RequestError as e:
            console.print(f"[bold red]Error scraping catalog from {url}: {e}[/bold red]")
            return []
        except Exception as e:
            console.print(f"[bold red]An unexpected error occurred during catalog scraping: {e}[/bold red]")
            return []


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
        ..., help="The app ID from the Apple App Store (e.g., 'facebook')."
    ),
    country: str = typer.Option(
        "us", "--country", "-c", help="The two-letter country code for the App Store."
    ),
    reviews: int = typer.Option(
        200, "--reviews", "-r", help="Number of recent reviews to analyze."
    ),
):
    """Analyzes Apple App Store reviews to estimate churn risk."""
    prodint = ProdInt()
    data = prodint.analyze_churn_risk(app_id, country, reviews)
    if data:
        console.print(
            f"[bold green]Churn & Sentiment Analysis for {app_id}:[/bold green]"
        )
        console.print_json(data=data)


@app.command(name="monitor-dev")
def monitor_dev(
    developer_name: str = typer.Argument(
        ..., help="The exact developer name as it appears on the Google Play Store."
    ),
    country: str = typer.Option(
        "us", "--country", "-c", help="The two-letter country code for the Play Store."
    ),
):
    """Monitors the Google Play Store for apps by a specific developer."""
    prodint = ProdInt()
    data = prodint.monitor_developer_apps(developer_name, country)
    if data:
        console.print(
            f"[bold green]App Store Monitor for Developer: {developer_name}[/bold green]"
        )
        console.print_json(data=data)


# --- NEW COMMANDS ---

@app.command(name="scrape-catalog")
def scrape_catalog(
    url: str = typer.Argument(
        ...,
        help="The URL of the e-commerce or marketplace catalog page to scrape.",
    )
):
    """
    (Best-effort) Scrapes product listings from a catalog page.
    """
    prodint = ProdInt()
    console.print(f"[bold cyan]Scraping product catalog from {url}...[/bold cyan]")
    catalog_data = asyncio.run(prodint.scrape_ecommerce_catalog(url))
    if catalog_data:
        console.print(
            f"[bold green]Successfully scraped {len(catalog_data)} products:[/bold green]"
        )
        console.print_json(data=catalog_data)
    else:
        console.print("[bold yellow]Could not scrape any products. The site may be protected or uses non-standard HTML.[/bold yellow]")


@app.command(name="monitor-changelog")
def monitor_changelog(
    url: str = typer.Option(
        ...,
        "--url",
        "-u",
        help="The URL of the release notes, changelog, or pricing page to monitor.",
    ),
    schedule: str = typer.Option(
        ...,
        "--schedule",
        "-s",
        help="Cron-style schedule (e.g., '0 0 * * *' for daily at midnight).",
    ),
):
    """
    Monitors a product changelog or pricing page for any changes.
    (This is a specialized use of the core 'page_monitor' module).
    """
    job_id = f"prodint_monitor_{sha256(url.encode()).hexdigest()[:10]}"

    try:
        add_job(
            func=check_for_changes,  # Reuse the core function
            trigger="cron",
            cron_schedule=schedule,
            job_id=job_id,
            kwargs={"url": url, "job_id": job_id},
        )
        console.print(
            "[bold green]✅ Successfully scheduled product page monitor.[/bold green]"
        )
        console.print(f"   - Job ID: {job_id}")
        console.print(f"   - URL: {url}")
        console.print(f"   - Schedule: {schedule}")
        console.print(
            "\nEnsure the Chimera daemon is running for the job to execute: [bold]chimera daemon start[/bold]"
        )
        logger.info(
            f"Successfully scheduled PRODINT job {job_id} for {url} with schedule '{schedule}'"
        )
    except Exception as e:
        console.print(f"[bold red]Error scheduling job:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command(name="feature-gaps")
def feature_gaps(
    our_url: str = typer.Option(
        ...,
        "--our-url",
        help="URL to our product's feature or pricing page."
    ),
    competitor_url: str = typer.Option(
        ...,
        "--competitor-url",
        help="URL to the competitor's feature or pricing page."
    ),
    requested_features: str = typer.Option(
        ...,
        "--requested",
        help="A comma-separated list of user-requested features (e.g., 'SSO,API,Dark Mode')."
    )
):
    """
    Automatically scrapes two feature pages and compares them against a list of requested features.
    """
    prodint = ProdInt()
    console.print("[bold cyan]Scraping feature lists...[/bold cyan]")

    async def scrape_all():
        task_ours = prodint.scrape_features_from_page(our_url)
        task_theirs = prodint.scrape_features_from_page(competitor_url)
        results = await asyncio.gather(task_ours, task_theirs)
        return results[0], results[1]

    our_features_list, competitor_features_list = asyncio.run(scrape_all())
    
    if not our_features_list:
        console.print(f"[bold yellow]Warning: Could not scrape any features from {our_url}.[/bold yellow]")
    if not competitor_features_list:
        console.print(f"[bold yellow]Warning: Could not scrape any features from {competitor_url}.[/bold yellow]")

    requested_features_list = [f.strip() for f in requested_features.split(',')]

    console.print("[bold cyan]Analyzing feature gaps...[/bold cyan]")
    gaps = prodint.find_feature_gaps(
        our_features_list, competitor_features_list, requested_features_list
    )

    console.print("\n[bold green]Feature Gap Analysis Results:[/bold green]")
    console.print_json(data=gaps)


if __name__ == "__main__":
    app()