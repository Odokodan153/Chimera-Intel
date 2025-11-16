"""
Module for SEO (Search Engine Optimization) & Content Intelligence.

Analyzes a target's keyword footprint, backlink profile, domain
authority, and content strategy against competitors.
"""

import typer
import logging
import json
import asyncio
from typing import List, Optional, Dict
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse
from .schemas import (
    SeoKeywordAnalysis,
    SeoKeywordPosition,
    SeoBacklinkReport,
    SeoContentVelocity,
    SeoIntelResult,
)
from .gemini_client import GeminiClient
from .utils import save_or_print_results, console, is_valid_domain
from .database import save_scan_to_db
from .project_manager import resolve_target
from .config_loader import API_KEYS
from .google_search import search as simple_google_search
from .web_analyzer import get_traffic_similarweb
from .topic_clusterer import run_topic_clustering


logger = logging.getLogger(__name__)
gemini_client = GeminiClient()
seo_intel_app = typer.Typer()

# --- Helper Function ---

def _get_domain(url: str) -> str:
    """Extracts the simple domain (e.g., 'example.com') from a URL."""
    try:
        parts = urlparse(url).netloc
        if parts:
            # Split to handle subdomains, get the last two parts
            domain_parts = parts.split('.')
            if len(domain_parts) > 1:
                return f"{domain_parts[-2]}.{domain_parts[-1]}"
        return "unknown"
    except Exception:
        return "unknown"


# --- Core Logic ---

def _analyze_keyword_gap(
    target_domain: str, competitors: List[str], keywords: List[str]
) -> List[SeoKeywordAnalysis]:
    """
    (REAL) Uses Google Search to analyze the top 10 SERP for keywords.
    This is a "real" analysis of who is currently ranking.
    """
    logger.info(f"Analyzing real SERP for {target_domain}...")
    analysis_results = []
    all_domains_to_track = [target_domain] + competitors

    for kw in keywords:
        kw_analysis = SeoKeywordAnalysis(keyword=kw)
        competitor_positions: Dict[str, List[SeoKeywordPosition]] = {
            c: [] for c in competitors
        }
        
        try:
            # 1. Perform a standard Google search for the keyword
            top_results = simple_google_search([kw], num_results=10)
            
            all_ranks: List[SeoKeywordPosition] = []
            target_ranks: List[SeoKeywordPosition] = []

            # 2. Analyze the top 10 results
            for i, url in enumerate(top_results, 1):
                domain = _get_domain(url)
                position = SeoKeywordPosition(rank=i, url=url, domain=domain)
                all_ranks.append(position)

                # 3. Check if the result belongs to the target or a competitor
                if domain == target_domain:
                    target_ranks.append(position)
                
                for comp_domain in competitors:
                    if domain == comp_domain:
                        competitor_positions[comp_domain].append(position)

            kw_analysis.top_10_ranks = all_ranks
            kw_analysis.target_positions = target_ranks
            kw_analysis.competitor_positions = competitor_positions
            
            # 4. Use AI to summarize the gap
            serp_summary = "\n".join(
                [f"Rank {p.rank}: {p.domain} ({p.url})" for p in all_ranks]
            )
            prompt = f"""
            As an SEO expert, analyze the top 10 search results for: "{kw}"
            
            Target Domain: {target_domain}
            Competitors: {', '.join(competitors)}

            SERP Data:
            {serp_summary}

            Briefly summarize the competitive gap. 
            - Does the target rank?
            - Are competitors dominating?
            - Is the page filled with non-competitor sites (e.g., news, forums), 
              indicating an opportunity?
            """
            summary = gemini_client.generate_response(prompt)
            if summary:
                kw_analysis.gap_summary = summary.strip()
                
        except Exception as e:
            logger.error(f"Failed during keyword SERP analysis for '{kw}': {e}")
            kw_analysis.gap_summary = f"Error during analysis: {e}"
        
        analysis_results.append(kw_analysis)
        
    return analysis_results

def _analyze_backlinks(target_domain: str) -> SeoBacklinkReport:
    """
    (REAL) Uses Google Search for "mention" analysis to find potential backlinks.
    This is a common OSINT technique and is much more reliable than the
    deprecated 'link:' operator.
    """
    logger.info(f"Analyzing backlinks (mentions) for {target_domain}...")
    
    # Search for mentions of the domain, excluding the domain itself.
    query = f'"{target_domain}" -site:{target_domain}'
    
    try:
        links = simple_google_search([query], num_results=50)
        
        domains = Counter(
            _get_domain(url) for url in links if _get_domain(url) != "unknown"
        )
        top_domains = [d[0] for d in domains.most_common(10)]

        return SeoBacklinkReport(
            query_used=query,
            total_mentions_found=len(links),
            top_mentioning_urls=links[:20], # Top 20 URLs
            top_mentioning_domains=top_domains
        )
    except Exception as e:
        logger.error(f"Failed during backlink (mention) analysis: {e}")
        return SeoBacklinkReport(
            query_used=query,
            total_mentions_found=0,
            top_mentioning_urls=[],
            top_mentioning_domains=[]
        )

def _analyze_content_velocity(
    documents: List[Dict[str, str]]
) -> SeoContentVelocity:
    """Analyzes publishing cadence from document timestamps."""
    logger.info("Analyzing content velocity...")
    month_year_counts = Counter()
    total_articles = 0

    for doc in documents:
        timestamp_str = doc.get("timestamp")
        if timestamp_str:
            try:
                # Try parsing ISO format, removing 'Z' if present
                dt = datetime.fromisoformat(timestamp_str.rstrip("Z"))
                month_year = dt.strftime("%Y-%m")
                month_year_counts[month_year] += 1
                total_articles += 1
            except ValueError:
                logger.warning(f"Could not parse timestamp: {timestamp_str}")
    
    avg = 0.0
    if total_articles > 0 and len(month_year_counts) > 0:
        avg = total_articles / len(month_year_counts)

    return SeoContentVelocity(
        total_articles=total_articles,
        articles_per_month=dict(month_year_counts.most_common()),
        average_per_month=round(avg, 2)
    )


async def _run_seo_analysis_async(
    target_domain: str, 
    competitors: List[str], 
    keywords: List[str],
    content_file: Optional[str]
) -> SeoIntelResult:
    """Async wrapper to gather all SEO data."""
    
    # 1. Get Traffic/Authority (Async)
    logger.info("Fetching traffic/authority data...")
    similarweb_key = API_KEYS.similarweb_api_key
    traffic_data = await get_traffic_similarweb(target_domain, similarweb_key)

    # 2. Analyze Keywords (Sync, but run in executor)
    loop = asyncio.get_running_loop()
    keyword_analysis = await loop.run_in_executor(
        None, _analyze_keyword_gap, target_domain, competitors, keywords
    )
    
    # 3. Analyze Backlinks (Sync, but run in executor)
    backlink_report = await loop.run_in_executor(
        None, _analyze_backlinks, target_domain
    )

    # 4. Analyze Content (Sync, if file provided)
    topic_coverage = None
    content_velocity = None
    if content_file:
        logger.info(f"Loading content file: {content_file}")
        try:
            with open(content_file, "r") as f:
                documents = json.load(f)
            if not isinstance(documents, list):
                raise ValueError("Content file must be a JSON list.")
            
            # Run topic coverage (re-used)
            topic_coverage = await loop.run_in_executor(
                None, run_topic_clustering, documents
            )
            # Run velocity analysis
            content_velocity = await loop.run_in_executor(
                None, _analyze_content_velocity, documents
            )
        except Exception as e:
            logger.error(f"Failed to process content file: {e}")

    return SeoIntelResult(
        target_domain=target_domain,
        competitors=competitors,
        keyword_analysis=keyword_analysis,
        backlink_report=backlink_report,
        traffic_authority=traffic_data,
        topic_coverage=topic_coverage,
        content_velocity=content_velocity
    )


@seo_intel_app.command("run")
def run_seo_analysis_cli(
    target: Optional[str] = typer.Argument(
        None, help="The target domain. Uses active project if not provided."
    ),
    competitors: List[str] = typer.Option(
        [], "--competitor", "-c", help="A competitor domain. Can be used multiple times."
    ),
    keywords: List[str] = typer.Option(
        [], "--keyword", "-k", help="A keyword to analyze. Can be used multiple times."
    ),
    content_file: Optional[str] = typer.Option(
        None,
        "--content-file",
        "-i",
        help="(Optional) Path to a JSON file of target's articles "
             "for velocity/topic analysis.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes SEO and Content strategy against competitors.
    """
    target_domain = resolve_target(target, required_assets=["domain"])
    if not is_valid_domain(target_domain):
        console.print(f"[bold red]Error:[/] Invalid target domain: {target_domain}")
        raise typer.Exit(code=1)
        
    for d in competitors:
        if not is_valid_domain(d):
            console.print(f"[bold red]Error:[/] Invalid competitor domain: {d}")
            raise typer.Exit(code=1)

    if not keywords and not content_file and not API_KEYS.similarweb_api_key:
         console.print(
             "[bold yellow]Warning:[/] No keywords, content file, "
             "or Similarweb API key provided. "
             "Running with basic backlink/mention analysis only."
         )

    with console.status(
        f"[bold cyan]Running SEO/Content analysis for {target_domain}...[/bold cyan]"
    ):
        results_model = asyncio.run(
            _run_seo_analysis_async(
                target_domain, competitors, keywords, content_file
            )
        )

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_domain, module="seo_intel", data=results_dict
    )