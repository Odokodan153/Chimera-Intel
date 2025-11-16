"""
Competitor Content & Narrative Tracker Module for Chimera Intel.

This module monitors a competitor's public content (blogs, resource 
centers, news, case studies) to analyze their strategic narratives.

It implements the functionality described by the user:
1.  Discover content (blogs, whitepapers, news) via Google Search.
2.  Scrape the text from discovered URLs.
3.  Summarize each piece of content individually.
4.  Cluster all content to identify high-level strategic themes.
"""

import typer
import asyncio
import logging
import httpx
from typing import Optional, Dict, Any, List
from chimera_intel.core.http_client import async_client
from chimera_intel.core.utils import console, save_or_print_results, is_valid_domain
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.project_manager import resolve_target
from chimera_intel.core.schemas import NarrativeAnalysisResult, ContentSummary, StrategicTheme

# --- Assumed Imports from other core modules ---
# These functions are assumed to exist based on the user request
# and their descriptions in other modules.

try:
    # Assumed to scrape a URL and return its main text content
    from .web_scraper import scrape_url_text
except ImportError:
    console.print(
        "[yellow]Warning:[/yellow] `web_scraper.scrape_url_text` not found. "
        "Text scraping will be skipped. Using snippets only."
    )
    # Create a mock function to allow the module to load
    async def scrape_url_text(url: str, **kwargs) -> str:
        logger.warning(f"Mock scrape_url_text called for {url}. Returning empty string.")
        return ""

try:
    # Assumed to take text and return an AI summary
    from .ai_core import get_summary
except ImportError:
    console.print(
        "[yellow]Warning:[/yellow] `ai_core.get_summary` not found. "
        "Content summarization will be skipped."
    )
    # Create a mock function
    async def get_summary(text: str, **kwargs) -> str:
        logger.warning("Mock get_summary called. Returning empty string.")
        return "Mock Summary (ai_core.py not found)"

try:
    # Assumed to take texts and return N cluster themes
    from .topic_clusterer import cluster_topics
except ImportError:
    console.print(
        "[yellow]Warning:[/yellow] `topic_clusterer.cluster_topics` not found. "
        "Theme clustering will be skipped."
    )
    # Create a mock function
    async def cluster_topics(texts: List[str], num_clusters: int = 5, **kwargs) -> List[Dict[str, Any]]:
        logger.warning("Mock cluster_topics called. Returning empty list.")
        return []


logger = logging.getLogger(__name__)
app = typer.Typer(
    no_args_is_help=True, help="Competitor Content & Narrative (NARINT) tools."
)


# --- Google CSE Search Functions ---
# Duplicated from 'sales_intel.py' to make this module
# self-contained for content discovery.


async def _search_google_cse(
    query: str, api_key: str, cse_id: str, num_results: int = 10
) -> Dict[str, Any]:
    """
    Performs a real search using the Google Custom Search Engine (CSE) API.
    """
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": api_key,
        "cx": cse_id,
        "q": query,
        "num": num_results,
    }
    try:
        response = await async_client.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except (httpx.HTTPStatusError, httpx.RequestError) as e:
        logger.error(f"Google CSE API search failed for '{query}': {e}")
        return {"error": str(e), "items": []}


async def _run_searches(
    queries: List[str], api_key: str, cse_id: str
) -> List[Dict[str, str]]:
    """Helper to run a list of Google CSE search queries in parallel."""
    console.print(f"Searching Google CSE for {len(queries)} queries...")
    search_tasks = [
        _search_google_cse(q, api_key, cse_id, num_results=10) for q in queries
    ]
    search_api_results = await asyncio.gather(*search_tasks)

    found_items = []
    for i, api_result in enumerate(search_api_results):
        if "error" in api_result:
            logger.warning(
                f"Google CSE API error for query '{queries[i]}': {api_result['error']}"
            )
            continue

        for item in api_result.get("items", []):
            found_items.append({
                "source_query": queries[i],
                "title": item.get("title"),
                "link": item.get("link"),
                "snippet": item.get("snippet"),
            })
    return found_items


# --- Narrative Analysis Core Logic ---

async def _analyze_content_item(item: Dict[str, str]) -> Optional[ContentSummary]:
    """
    Scrapes, then summarizes, a single piece of content.
    """
    url = item.get("link")
    if not url:
        return None

    try:
        # Step 1: Scrape full text content
        console.print(f"   Scraping: [dim]{url}[/dim]")
        full_text = await scrape_url_text(url)
        
        if not full_text:
            logger.warning(f"No text content found for {url}, using snippet.")
            # Fallback to snippet if scraping fails
            full_text = item.get("snippet", "")

        # Step 2: Get AI summary
        console.print(f"   Summarizing: [dim]{item.get('title')}[/dim]")
        summary = await get_summary(full_text)

        return ContentSummary(
            title=item.get("title", "No Title"),
            url=url,
            source_query=item.get("source_query", ""),
            snippet=item.get("snippet", ""),
            ai_summary=summary,
            full_text=full_text,  # Include full text for clustering
        )
    except Exception as e:
        logger.error(f"Failed to analyze content item {url}: {e}")
        return None


@app.command(name="analyze-themes")
def analyze_themes(
    domain: Optional[str] = typer.Argument(
        None, help="The target domain. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Analyzes a competitor's content themes from their blogs,
    resource centers, and news mentions.
    """
    target_domain = resolve_target(domain, required_assets=["domain"])
    if not is_valid_domain(target_domain):
        console.print(f"[red]Invalid domain:[/red] '{target_domain}'")
        raise typer.Exit(code=1)

    # Check for required API keys
    google_api_key = API_KEYS.google_api_key
    google_cse_id = API_KEYS.google_cse_id
    if not google_api_key or not google_cse_id:
        console.print(
            "[red]Error: 'google_api_key' and 'google_cse_id' must be set.[/red]"
        )
        raise typer.Exit(code=1)

    console.print(
        f"Hunting for competitor content narratives for {target_domain}..."
    )

    # Define queries to find competitor content
    search_queries = [
        f'site:{target_domain} "blog" OR "article" OR "resource"',
        f'site:{target_domain} "case study" OR "customer story" OR "whitepaper"',
        f'"{target_domain}" "announces" OR "launches" OR "partners with"',
        # Note: YouTube video analysis requires a separate transcription
        # pipeline (e.g., vidint.py) which is not integrated here.
        # f'site:youtube.com "{target_domain}"'
    ]

    async def run_full_analysis():
        # Step 1: Discover Content
        discovered_items = await _run_searches(
            search_queries, google_api_key, google_cse_id
        )
        if not discovered_items:
            console.print("[yellow]No content items found.[/yellow]")
            return None

        console.print(
            f"[green]Discovered {len(discovered_items)} potential content items.[/green]"
        )
        console.print("Analyzing content (scraping and summarizing)...")

        # Step 2: Scrape and Summarize all content in parallel
        analysis_tasks = [
            _analyze_content_item(item) for item in discovered_items
        ]
        content_summaries = await asyncio.gather(*analysis_tasks)
        
        # Filter out failed analyses and empty text
        valid_summaries = [
            cs for cs in content_summaries 
            if cs and cs.full_text and len(cs.full_text) > 100
        ]
        
        if not valid_summaries:
            console.print("[red]Content analysis failed for all items.[/red]")
            return None
        
        console.print(
            f"[green]Successfully analyzed {len(valid_summaries)} content items.[/green]"
        )

        # Step 3: Cluster Topics
        console.print("Clustering strategic themes...")
        all_texts = [cs.full_text for cs in valid_summaries]
        
        # This call is assumed to be async
        theme_results = await cluster_topics(all_texts, num_clusters=5) 
        
        strategic_themes = [
            StrategicTheme(
                theme_name=t.get("theme_name", f"Theme {i+1}"),
                keywords=t.get("keywords", []),
                representative_docs=t.get("representative_docs", [])
            ) for i, t in enumerate(theme_results)
        ]
        
        console.print(f"[green]Identified {len(strategic_themes)} strategic themes.[/green]")
        for theme in strategic_themes:
            console.print(f"  - [bold]{theme.theme_name}[/bold]: {', '.join(theme.keywords)}")

        # Combine results
        final_report = NarrativeAnalysisResult(
            target_domain=target_domain,
            strategic_themes=strategic_themes,
            content_summaries=valid_summaries,
        )
        return final_report

    try:
        results = asyncio.run(run_full_analysis())
        if results:
            results_dict = results.model_dump(exclude_none=True, exclude={"full_text"})
            save_or_print_results(results_dict, output_file)
    except Exception as e:
        logger.error(f"Error in narrative analysis: {e}", exc_info=True)
        console.print(f"[red]An error occurred: {e}[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()