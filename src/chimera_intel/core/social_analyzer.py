import typer
import feedparser
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from rich.panel import Panel
from typing import List, Optional
import logging
from httpx import RequestError, HTTPStatusError

# --- CORRECTED Absolute Imports ---

from chimera_intel.core.utils import save_or_print_results, is_valid_domain, console
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.http_client import sync_client

# Import the Pydantic models for type-safe results

from chimera_intel.core.schemas import (
    SocialContentAnalysis,
    SocialAnalysisResult,
    AnalyzedPost,
)

# Get a logger instance for this specific file

logger = logging.getLogger(__name__)

# --- AI Model Initialization ---

try:
    from transformers import pipeline

    classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
except (ImportError, OSError):
    classifier = None
# --- Core Functions ---


def discover_rss_feed(domain: str) -> Optional[str]:
    """
    Tries to automatically discover the RSS feed URL from a domain's homepage or sitemap.

    Args:
        domain (str): The domain to search for an RSS feed.

    Returns:
        Optional[str]: The full URL of the discovered RSS feed if found, otherwise None.
    """
    base_url = f"https://www.{domain}"
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = sync_client.get(base_url, headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            rss_link = soup.find("link", {"type": "application/rss+xml"})
            if rss_link and rss_link.has_attr("href"):
                return urljoin(base_url, rss_link["href"])
    except (HTTPStatusError, RequestError) as e:
        logger.warning(
            "Could not fetch homepage for RSS discovery on '%s': %s", domain, e
        )
        pass  # Silently ignore and try the next method
    sitemap_url = urljoin(base_url, "/sitemap.xml")
    try:
        response = sync_client.get(sitemap_url, headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, "xml")
            for loc in soup.find_all("loc"):
                url_text = loc.text.lower()
                if "rss" in url_text or "feed" in url_text:
                    return loc.text
    except (HTTPStatusError, RequestError) as e:
        logger.warning(
            "Could not fetch sitemap for RSS discovery on '%s': %s", domain, e
        )
        pass
    return None


def analyze_feed_content(feed_url: str, num_posts: int = 5) -> SocialContentAnalysis:
    """
    Parses an RSS feed and analyzes the content of the latest posts using a zero-shot AI model.

    Args:
        feed_url (str): The URL of the RSS feed to analyze.
        num_posts (int): The number of recent posts to analyze. Defaults to 5.

    Returns:
        SocialContentAnalysis: A Pydantic model containing the analysis results or an error.
    """
    if not classifier:
        return SocialContentAnalysis(
            feed_title="N/A",
            posts=[],
            error="AI analysis skipped. 'transformers' not installed.",
        )
    try:
        feed = feedparser.parse(feed_url)
        if feed.bozo:
            logger.warning(
                "The RSS feed at %s might be malformed. Analysis may be incomplete.",
                feed_url,
            )
        posts_analysis: List[AnalyzedPost] = []
        candidate_labels = [
            "Product Launch",
            "Financial Results",
            "Partnerships",
            "Hiring / Careers",
            "Company Culture",
            "Technical Update",
            "Security Advisory",
        ]

        for entry in feed.entries[:num_posts]:
            title = entry.get("title", "No Title")
            content_to_analyze = entry.get("summary", "")
            if hasattr(entry, "content"):
                content_to_analyze = entry.content[0].value
            clean_content = BeautifulSoup(content_to_analyze, "html.parser").get_text(
                separator=" ", strip=True
            )
            classification = classifier(
                f"{title}. {clean_content[:512]}", candidate_labels
            )

            posts_analysis.append(
                AnalyzedPost(
                    title=title,
                    link=entry.get("link", "#"),
                    top_category=classification["labels"][0],
                    confidence=f"{classification['scores'][0]:.2%}",
                )
            )
        return SocialContentAnalysis(
            feed_title=feed.feed.get("title", "Unknown Feed"), posts=posts_analysis
        )
    except Exception as e:
        logger.error("Failed to parse or analyze the feed at %s: %s", feed_url, e)
        return SocialContentAnalysis(
            feed_title="N/A",
            posts=[],
            error=f"Failed to parse or analyze the feed: {e}",
        )


# --- Typer CLI Application ---

social_app = typer.Typer()


@social_app.command("run")
def run_social_analysis(
    domain: str = typer.Argument(
        ..., help="The target domain to find and analyze a blog/RSS feed for."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Finds and analyzes the content of a target's RSS feed for strategic topics.
    """
    if not is_valid_domain(domain):
        logger.warning("Invalid domain format provided to 'social' command: %s", domain)
        console.print(
            Panel(
                f"[bold red]Invalid Input:[/] '{domain}' is not a valid domain format.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    if not classifier:
        logger.warning("AI libraries not found. AI content analysis will be skipped.")
    logger.info("Starting social content analysis for %s", domain)

    feed_url = discover_rss_feed(domain)

    if not feed_url:
        logger.error("Could not automatically discover an RSS feed for %s.", domain)
        raise typer.Exit(code=1)
    logger.info("Feed found: %s", feed_url)

    analysis_results = analyze_feed_content(feed_url)

    results_model = SocialAnalysisResult(
        domain=domain, social_content_analysis=analysis_results
    )

    results_dict = results_model.model_dump()

    logger.info("Social content analysis complete for %s", domain)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=domain, module="social_analyzer", data=results_dict)
