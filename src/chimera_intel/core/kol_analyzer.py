"""
Module for Key Opinion Leader (KOL) / Influencer Identification.

Analyzes news articles and web content to identify and rank
the most influential people within a specific industry or topic.
"""

import typer
import logging
import json
from typing import List, Optional, Dict, Any
from bs4 import BeautifulSoup

from chimera_intel.core.google_search import search as google_search
from chimera_intel.core.gemini_client import GeminiClient
from chimera_intel.core.schemas import KOLAnalysisResult, KeyOpinionLeader
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.utils import save_or_print_results, console
from chimera_intel.core.http_client import sync_client

logger = logging.getLogger(__name__)
kol_analyzer_app = typer.Typer()


def _scrape_text_from_url(url: str) -> str:
    """
    Fetches and extracts clean text content from a single URL.
    Uses the global sync_client which has built-in retries.
    """
    try:
        response = sync_client.get(url, timeout=10)
        response.raise_for_status()
        
        # Use BeautifulSoup to parse HTML and extract text
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Remove script and style elements
        for script_or_style in soup(["script", "style"]):
            script_or_style.decompose()
            
        # Get text, split into lines, and strip whitespace
        lines = (line.strip() for line in soup.get_text().splitlines())
        # Re-join lines, separated by a space
        text = " ".join(line for line in lines if line)
        
        # Return a snippet to avoid massive prompts
        return text[:3000]
    except Exception as e:
        logger.warning(f"Failed to scrape URL {url}: {e}")
        return ""


def run_kol_analysis(industry_topic: str, limit: int = 10) -> KOLAnalysisResult:
    """
    Identifies and ranks KOLs for a given industry topic by
    searching for articles and analyzing their content with an LLM.
    
    Args:
        industry_topic (str): The industry or topic to analyze 
                              (e.g., "Generative AI", "Cybersecurity").
        limit (int): The number of search results to analyze.

    Returns:
        KOLAnalysisResult: A Pydantic model with the ranked list of KOLs.
    """
    console.print(
        f"[cyan]Starting KOL analysis for industry: [bold]{industry_topic}[/bold][/cyan]"
    )
    gemini = GeminiClient()
    if not gemini.model:
        return KOLAnalysisResult(
            industry_query=industry_topic,
            error="Gemini client not initialized. Check API key."
        )

    # 1. Search for relevant articles
    with console.status("[cyan]Searching for relevant articles...[/cyan]"):
        try:
            search_queries = [
                f"top experts in {industry_topic}",
                f"key opinion leaders in {industry_topic}",
                f"{industry_topic} industry analysis"
            ]
            urls = google_search(search_queries, num_results=limit)
            if not urls:
                return KOLAnalysisResult(
                    industry_query=industry_topic, 
                    error="No articles found for this topic."
                )
        except Exception as e:
            return KOLAnalysisResult(
                industry_query=industry_topic, 
                error=f"Google search failed: {e}"
            )

    # 2. Scrape content from URLs
    with console.status(f"[cyan]Scraping {len(urls)} articles...[/cyan]"):
        scraped_content = []
        for url in urls:
            text = _scrape_text_from_url(url)
            if text:
                scraped_content.append(f"--- Article from {url} ---\n{text}\n")
        
        if not scraped_content:
            return KOLAnalysisResult(
                industry_query=industry_topic,
                error="Could not scrape content from any found URLs."
            )
    
    full_text = "\n".join(scraped_content)

    # 3. Use LLM to analyze text and extract KOLs
    with console.status("[cyan]Analyzing content for KOLs with AI...[/cyan]"):
        prompt = f"""
You are an expert market intelligence analyst. Your task is to identify the top 5-10 Key Opinion Leaders (KOLs), influencers, or top experts based on a collection of recent articles about "{industry_topic}".

Analyze the provided text below. Identify the most frequently mentioned and influential *people*.

Instructions:
1.  Read all the article snippets.
2.  Identify individuals who are cited as experts, leaders, CEOs, or influential figures.
3.  Rank them based on their apparent influence or frequency of mention.
4.  Return *only* a JSON list of objects. Each object must have:
    - "rank" (int): The rank, starting from 1.
    - "name" (str): The full name of the person.
    - "description" (str): A brief (1-2 sentence) description of why they are influential (e.g., "CEO of ExampleCorp", "Lead Researcher at Institute X", "Prominent industry analyst").

--- BEGIN ARTICLE CONTENT ---
{full_text}
--- END ARTICLE CONTENT ---

Return *only* the JSON list.
"""
        
        llm_response = gemini.generate_response(prompt)
        if not llm_response:
            return KOLAnalysisResult(
                industry_query=industry_topic,
                error="AI analysis returned an empty response."
            )

    # 4. Parse the result
    try:
        # Clean the response to ensure it's valid JSON
        json_str = llm_response.strip().lstrip("```json").rstrip("```")
        kols_data = json.loads(json_str)
        
        kols_list = [KeyOpinionLeader(**kol) for kol in kols_data]
        
        return KOLAnalysisResult(
            industry_query=industry_topic,
            total_kols_found=len(kols_list),
            kols=kols_list,
            source_urls_analyzed=urls
        )
        
    except json.JSONDecodeError:
        logger.error(f"Failed to decode LLM JSON response: {llm_response}")
        return KOLAnalysisResult(
            industry_query=industry_topic,
            error="Failed to parse AI response. The response was not valid JSON."
        )
    except Exception as e:
        logger.error(f"Failed to create Pydantic models: {e}")
        return KOLAnalysisResult(
            industry_query=industry_topic,
            error=f"AI response format was incorrect: {e}"
        )


@kol_analyzer_app.command("run")
def run_kol_analysis_cli(
    industry_topic: str = typer.Argument(
        ..., 
        help="The industry or topic to analyze (e.g., 'Generative AI')."
    ),
    limit: int = typer.Option(
        10,
        "--limit",
        "-l",
        help="Number of top Google search results to analyze."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Finds and ranks Key Opinion Leaders (KOLs) for an industry.
    """
    results_model = run_kol_analysis(industry_topic, limit)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=industry_topic,
        module="kol_analyzer",
        data=results_dict,
    )