"""
Market & Demand Intelligence Module.

Provides functionality for estimating market size (TAM/SAM/SOM),
tracking demand trends using Google Trends and news clustering,
and discovering product/feature categories.
"""

import typer
import asyncio
import logging
import json
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from pytrends.request import TrendReq  # type: ignore
from bs4 import BeautifulSoup
import time

from chimera_intel.core.utils import save_or_print_results, console
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.http_client import async_client
from chimera_intel.core.ai_core import generate_swot_from_data, SWOTAnalysisResult
from chimera_intel.core.google_search import search as google_search
from chimera_intel.core.topic_clusterer import run_topic_clustering
from chimera_intel.core.business_intel import get_news_gnews
from chimera_intel.core.schemas import TopicClusteringResult, GNewsArticle, GNewsResult
from .project_manager import resolve_target

logger = logging.getLogger(__name__)

# --- Pydantic Schemas for Market Demand ---

class TAMAnalysis(BaseModel):
    tam: str = Field(..., description="Estimated Total Addressable Market")
    sam: str = Field(..., description="Estimated Serviceable Addressable Market")
    som: str = Field(..., description="Estimated Serviceable Obtainable Market")
    methodology: str = Field(
        ..., description="Methodology and data sources used for the estimation"
    )
    key_data_points: List[str] = Field(
        default_factory=list, description="Key data points found in sources"
    )
    error: Optional[str] = None

class TrendDataPoint(BaseModel):
    date: str
    value: int

class TrendAnalysis(BaseModel):
    keyword: str
    interest_over_time: List[TrendDataPoint] = Field(default_factory=list)
    emerging_topics_cluster: Optional[TopicClusteringResult] = None
    ai_summary: Optional[str] = None

class MarketDemandResult(BaseModel):
    target_industry: str
    target_keywords: List[str]
    tam_analysis: Optional[TAMAnalysis] = None
    trend_analysis: Optional[List[TrendAnalysis]] = None
    category_clusters: Optional[TopicClusteringResult] = None
    error: Optional[str] = None

# --- Helper Functions ---

async def _scrape_urls(urls: List[str]) -> str:
    """Scrapes text content from a list of URLs."""
    headers = {"User-Agent": "Mozilla/5.0"}
    all_text = ""

    async def fetch_one(url):
        try:
            response = await async_client.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            paragraphs = " ".join([p.get_text() for p in soup.find_all("p")])
            return url, paragraphs[:2000]  # Limit text per URL
        except Exception as e:
            logger.warning("Failed to scrape URL %s: %s", url, e)
            return url, None

    results = await asyncio.gather(*[fetch_one(url) for url in urls])

    for url, text in results:
        if text:
            all_text += f"--- Source: {url} ---\n{text}\n\n"
    return all_text


def _get_google_trends(keywords: List[str], timeframe="today 12-m", geo="US") -> Dict:
    """Fetches Google Trends data. This is a blocking (sync) call."""
    try:
        pytrends = TrendReq(hl="en-US", tz=360)
        pytrends.build_payload(keywords, cat=0, timeframe=timeframe, geo=geo, gprop="")
        
        interest_over_time = pytrends.interest_over_time()
        
        trends_data = {}
        if not interest_over_time.empty:
            for kw in keywords:
                if kw in interest_over_time.columns:
                    trends_data[kw] = [
                        TrendDataPoint(date=str(index.date()), value=row[kw])
                        for index, row in interest_over_time.iterrows()
                    ]
        return trends_data
    except Exception as e:
        logger.error("Google Trends request failed: %s", e)
        return {"error": str(e)}

# --- Core Functions ---

async def estimate_tam_sam_som(
    industry: str, product_category: str, country: Optional[str] = None
) -> TAMAnalysis:
    """
    Estimates TAM/SAM/SOM by searching for public reports and synthesizing with AI.
    Reuses: google_search, ai_core.generate_swot_from_data
    """
    google_api_key = API_KEYS.google_api_key
    if not google_api_key:
        return TAMAnalysis(
            tam="N/A", sam="N/A", som="N/A", methodology="Error",
            error="Google API key not found. AI analysis is required."
        )

    location = f"in {country}" if country else "globally"
    query = f'"{industry}" "{product_category}" market size {location} TAM SAM SOM'
    query_reports = f'"{industry}" industry analysis report {location} market share'

    with console.status("[bold cyan]Searching for market size data...[/bold cyan]"):
        try:
            # Reuse google_search module
            search_urls = google_search([query, query_reports], num_results=5)
        except Exception as e:
            return TAMAnalysis(tam="N/A", sam="N/A", som="N/A", methodology="Error", error=f"Google search failed: {e}")

    if not search_urls:
        return TAMAnalysis(
            tam="N/A", sam="N/A", som="N/A",
            methodology="No data found.",
            error="No public data sources found for the query."
        )

    with console.status("[bold cyan]Scraping and analyzing reports...[/bold cyan]"):
        scraped_data = await _scrape_urls(search_urls)

    if not scraped_data:
        return TAMAnalysis(
            tam="N/A", sam="N/A", som="N/A",
            methodology="Data found but could not be scraped.",
            error="Found URLs but failed to scrape content for analysis."
        )

    prompt = f"""
    As a market research analyst, estimate the TAM, SAM, and SOM for a product in the
    '{product_category}' category within the '{industry}' industry, {location}.

    Base your analysis *only* on the following scraped data from public web reports.
    If specific numbers aren't available, provide a qualitative assessment.
    Always cite the source URL for any numbers you find.

    Output Format:
    - **TAM (Total Addressable Market):** [Your estimation, e.g., "$10B (Source: ...)" or "Very Large (Source: ..._)]
    - **SAM (Serviceable Addressable Market):** [Your estimation]
    - **SOM (Serviceable Obtainable Market):** [Your estimation]
    - **Key Data Points:** [Bullet list of numbers, percentages, or key quotes found]
    - **Methodology:** [Explain how you derived the estimates from the data]

    **Scraped Data:**
    ---
    {scraped_data}
    ---
    """

    with console.status("[bold cyan]AI is estimating market size...[/bold cyan]"):
        # Reuse ai_core module
        ai_result: SWOTAnalysisResult = generate_swot_from_data(prompt, google_api_key)

    if ai_result.error:
        return TAMAnalysis(
            tam="N/A", sam="N/A", som="N/A",
            methodology="AI analysis failed", error=ai_result.error
        )
    
    # This is a simplified parser. A real implementation might use
    # structured output from the LLM.
    text = ai_result.analysis_text
    return TAMAnalysis(
        tam=text.split("TAM (Total Addressable Market):**")[1].split("\n")[0].strip(),
        sam=text.split("SAM (Serviceable Addressable Market):**")[1].split("\n")[0].strip(),
        som=text.split("SOM (Serviceable Obtainable Market):**")[1].split("\n")[0].strip(),
        methodology=text.split("Methodology:**")[1].split("\n\n")[0].strip(),
        key_data_points=[k.strip() for k in text.split("Key Data Points:**")[1].split("\n-")[1:]]
    )


async def track_demand_trends(
    keywords: List[str], geo: str = "US"
) -> List[TrendAnalysis]:
    """
    Tracks demand by combining Google Trends, news analysis, and topic clustering.
    Reuses: business_intel.get_news_gnews, topic_clusterer.run_topic_clustering, ai_core
    """
    gnews_key = API_KEYS.gnews_api_key
    google_api_key = API_KEYS.google_api_key
    
    if not gnews_key or not google_api_key:
        logger.warning("GNews or Google API key missing, trend analysis will be limited.")

    loop = asyncio.get_running_loop()
    
    # 1. Get Google Trends Data (Sync, run in executor)
    with console.status("[bold cyan]Fetching Google Trends data...[/bold cyan]"):
        trends_data = await loop.run_in_executor(None, _get_google_trends, keywords, "today 12-m", geo)

    if trends_data.get("error"):
        return [TrendAnalysis(keyword=kw, error=trends_data["error"]) for kw in keywords]

    analysis_results: List[TrendAnalysis] = []
    
    for kw in keywords:
        trend_analysis = TrendAnalysis(keyword=kw)
        trend_analysis.interest_over_time = trends_data.get(kw, [])
        
        if gnews_key:
            # 2. Get News Data (Async)
            with console.status(f"[bold cyan]Gathering news for '{kw}'...[/bold cyan]"):
                news_result: GNewsResult = await get_news_gnews(f'"{kw}"', gnews_key)
            
            if news_result.articles:
                docs = [
                    {"content": f"{a.title} {a.description}", "source": a.source.name}
                    for a in news_result.articles
                ]
                
                # 3. Cluster News Topics (Sync, run in executor)
                with console.status(f"[bold cyan]Clustering news topics for '{kw}'...[/bold cyan]"):
                    # Reuse topic_clusterer module
                    cluster_result: TopicClusteringResult = await loop.run_in_executor(
                        None, run_topic_clustering, docs
                    )
                trend_analysis.emerging_topics_cluster = cluster_result

                # 4. AI Summary (Async)
                prompt = f"""
                As a market analyst, analyze the demand trend for '{kw}'.
                Combine the Google Trends data (scaled 0-100) and the clustered
                news topics to provide a summary.

                - Google Trends Summary: {trends_data.get(kw, 'No data')}
                - Emerging News Themes: {[c.cluster_name for c in cluster_result.clusters]}

                Provide a 2-3 sentence summary of the overall demand trend.
                Is it growing, declining, or stable? What news topics are driving this?
                """
                with console.status(f"[bold cyan]AI synthesizing trend for '{kw}'...[/bold cyan]"):
                    ai_summary = generate_swot_from_data(prompt, google_api_key)
                    if not ai_summary.error:
                        trend_analysis.ai_summary = ai_summary.analysis_text
        
        analysis_results.append(trend_analysis)
        
    return analysis_results


async def discover_categories(
    topic: str,
) -> TopicClusteringResult:
    """
    Discovers product/feature categories by scraping search results and clustering them.
    Reuses: google_search, topic_clusterer.run_topic_clustering
    """
    query = f'"{topic}" features OR "{topic}" use cases OR "{topic}" product categories'
    with console.status(f"[bold cyan]Searching for categories related to '{topic}'...[/bold cyan]"):
        try:
            search_urls = google_search([query], num_results=10)
        except Exception as e:
            return TopicClusteringResult(clusters=[], error=f"Google search failed: {e}")
    
    if not search_urls:
        return TopicClusteringResult(clusters=[], error="No search results found for topic.")
        
    with console.status("[bold cyan]Scraping features and use cases...[/bold cyan]"):
        scraped_data = await _scrape_urls(search_urls)
    
    if not scraped_data:
        return TopicClusteringResult(clusters=[], error="Failed to scrape content from search results.")

    # Create documents from scraped text snippets (e.g., split by source)
    documents = [
        {"content": snippet} 
        for snippet in scraped_data.split("--- Source: ") 
        if snippet.strip()
    ]
    
    with console.status("[bold cyan]Clustering categories...[/bold cyan]"):
        loop = asyncio.get_running_loop()
        # Reuse topic_clusterer module (is sync, so use executor)
        cluster_result: TopicClusteringResult = await loop.run_in_executor(
            None, run_topic_clustering, documents
        )
            
    return cluster_result

# --- Typer CLI Application ---

market_demand_app = typer.Typer()

@market_demand_app.command("tam")
def run_tam_estimator(
    industry: str = typer.Argument(..., help="The target industry (e.g., 'Cloud Computing')."),
    product_category: str = typer.Argument(..., help="The specific product category (e.g., 'IaaS')."),
    country: Optional[str] = typer.Option(None, "--country", "-c", help="Country to focus on (e.g., 'USA')."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file."),
):
    """Estimates TAM/SAM/SOM from public data and AI synthesis."""
    
    async def main():
        return await estimate_tam_sam_som(industry, product_category, country)
        
    results_model = asyncio.run(main())
    results_dict = results_model.model_dump(exclude_none=True)
    
    save_or_print_results(results_dict, output_file)
    target_name = f"{industry}_{product_category}_tam"
    save_scan_to_db(target=target_name, module="market_demand_tam", data=results_dict)

@market_demand_app.command("trends")
def run_trend_tracker(
    keywords: List[str] = typer.Argument(..., help="List of keywords to track."),
    geo: str = typer.Option("US", help="Geography code (e.g., 'US', 'GB')."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file."),
):
    """Tracks demand trends using Google Trends and news clustering."""
    
    async def main():
        return await track_demand_trends(keywords, geo)

    results_model = asyncio.run(main())
    results_dict = {"trends": [r.model_dump(exclude_none=True) for r in results_model]}
    
    save_or_print_results(results_dict, output_file)
    target_name = f"{keywords[0]}_trends"
    save_scan_to_db(target=target_name, module="market_demand_trends", data=results_dict)

@market_demand_app.command("categories")
def run_category_discovery(
    topic: str = typer.Argument(..., help="Main topic to find categories for (e.g., 'CRM Software')."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file."),
):
    """Discovers and clusters features, products, or use cases for a topic."""
    
    async def main():
        return await discover_categories(topic)
        
    results_model = asyncio.run(main())
    results_dict = results_model.model_dump(exclude_none=True)
    
    save_or_print_results(results_dict, output_file)
    target_name = f"{topic}_categories"
    save_scan_to_db(target=target_name, module="market_demand_categories", data=results_dict)