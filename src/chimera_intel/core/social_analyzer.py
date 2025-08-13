import typer
import feedparser
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
# --- CORRECTED Absolute Imports ---
from chimera_intel.core.utils import save_or_print_results
from chimera_intel.core.database import save_scan_to_db

console = Console()

# --- AI Model Initialization ---
# This block will try to import the necessary libraries and initialize the AI model.
# If the libraries are not installed, it will set the classifier to None and handle it gracefully.
try:
    from transformers import pipeline
    # This is a powerful model that can classify text into categories you provide on the fly,
    # without needing to be pre-trained on them.
    classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
except ImportError:
    classifier = None

# --- Core Functions ---

def discover_rss_feed(domain: str) -> str | None:
    """
    Tries to automatically discover the RSS feed URL from a domain's homepage.

    Args:
        domain (str): The domain to search.

    Returns:
        str | None: The URL of the RSS feed if found, otherwise None.
    """
    urls_to_try = [f"https://{domain}", f"https://www.{domain}"]
    headers = {"User-Agent": "Mozilla/5.0"}
    for url in urls_to_try:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                # Look for the standard RSS link tag in the page's head
                rss_link = soup.find("link", {"type": "application/rss+xml"})
                if rss_link and rss_link.has_attr('href'):
                    feed_url = rss_link['href']
                    # Ensure the URL is absolute by joining it with the base URL if necessary
                    if not feed_url.startswith(('http:', 'https:')):
                        from urllib.parse import urljoin
                        feed_url = urljoin(url, feed_url)
                    return feed_url
        except requests.RequestException:
            # Silently ignore connection errors and try the next URL
            continue
    return None

def analyze_feed_content(feed_url: str, num_posts: int = 5) -> dict:
    """
    Parses an RSS feed and analyzes the content of the latest posts using an AI model.

    Args:
        feed_url (str): The URL of the RSS feed.
        num_posts (int): The number of recent posts to analyze.

    Returns:
        dict: A dictionary containing the analysis of the feed posts.
    """
    if not classifier:
        return {"error": "The 'transformers' or 'torch' library is not installed."}
        
    try:
        # Use the feedparser library to parse the RSS feed
        feed = feedparser.parse(feed_url)
        posts_analysis = []
        
        # Define the strategic categories we want to classify posts into.
        candidate_labels = ["Product Launch", "Financial Results", "Partnerships", "Hiring / Careers", "Company Culture", "Technical Update"]

        # Analyze the most recent posts, up to the num_posts limit
        for entry in feed.entries[:num_posts]:
            title = entry.get("title", "No Title")
            link = entry.get("link", "#")
            summary = entry.get("summary", "")
            
            # Use the AI model to classify the post's title and summary
            classification = classifier(f"{title}. {summary}", candidate_labels)
            
            posts_analysis.append({
                "title": title,
                "link": link,
                "top_category": classification['labels'][0],
                "confidence": f"{classification['scores'][0]:.2%}"
            })
            
        return {"feed_title": feed.feed.get("title", "Unknown Feed"), "posts": posts_analysis}

    except Exception as e:
        return {"error": f"Failed to parse or analyze the feed: {e}"}


# --- Typer CLI Application ---

social_app = typer.Typer()

@social_app.command("run")
def run_social_analysis(
    domain: str = typer.Argument(..., help="The target domain to find and analyze a blog/RSS feed for."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save the results to a JSON file.")
):
    """
    Finds and analyzes the content of a target's RSS feed for strategic topics.
    """
    console.print(Panel(f"[bold magenta]Starting Social Content Analysis For:[/] {domain}", title="Chimera Intel | Social Analyzer", border_style="magenta"))

    console.print(f" [cyan]>[/cyan] Discovering RSS feed for {domain}...")
    feed_url = discover_rss_feed(domain)
    
    if not feed_url:
        console.print(f"[bold red]Error:[/] Could not automatically discover an RSS feed for {domain}.")
        raise typer.Exit(code=1)
        
    console.print(f"   [green]✓[/green] Feed found: {feed_url}")
    
    console.print(" [cyan]>[/cyan] Analyzing recent posts with AI...")
    analysis_results = analyze_feed_content(feed_url)
    
    # --- Structure Final Results ---
    results = {
        "domain": domain,
        "social_content_analysis": analysis_results
    }
    
    console.print("\n[bold green]Social Content Analysis Complete![/bold green]")
    save_or_print_results(results, output_file)
    save_scan_to_db(target=domain, module="social_analyzer", data=results)