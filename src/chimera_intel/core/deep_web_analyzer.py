"""
Module for Deep Web Intelligence.

Uses Google Custom Search Engine (CSE) API to search within
specific sites like academic portals, journals, and databases.
"""

import typer
import logging
from typing import Optional
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.database import save_scan_to_db
from .schemas import DeepWebResult, DeepWebHit

logger = logging.getLogger(__name__)
deep_web_app = typer.Typer()


def search_deep_web(
    query: str,
    custom_search_engine_id: str,
    num_results: int = 10,
) -> DeepWebResult:
    """
    Performs a search using a Google Custom Search Engine.
    """
    api_key = API_KEYS.google_api_key
    if not api_key:
        return DeepWebResult(query=query, cse_id=custom_search_engine_id, error="GOOGLE_API_KEY not found in config.")
    if not custom_search_engine_id:
        return DeepWebResult(query=query, cse_id=custom_search_engine_id, error="No Google CSE ID provided.")

    result = DeepWebResult(query=query, cse_id=custom_search_engine_id)

    try:
        service = build("customsearch", "v1", developerKey=api_key)
        cse = service.cse()
        
        # Google CSE API max is 10 results at a time
        request_num = min(num_results, 10)
        
        response = cse.list(
            q=query,
            cx=custom_search_engine_id,
            num=request_num
        ).execute()

        items = response.get("items", [])
        result.hits = [
            DeepWebHit(
                title=item.get("title"),
                link=item.get("link"),
                snippet=item.get("snippet"),
                source=item.get("displayLink")
            ) for item in items
        ]
        
        search_info = response.get("searchInformation", {})
        total_str = search_info.get("totalResults", "0")
        result.total_results = int(total_str)

    except HttpError as e:
        logger.error(f"Google CSE API HttpError: {e}")
        result.error = f"HTTP Error: {e.resp.status} {e.resp.reason}"
    except Exception as e:
        logger.error(f"An error occurred during deep web search: {e}")
        result.error = str(e)

    return result


# --- CLI Command ---

@deep_web_app.command("search")
def run_deep_web_search(
    query: str = typer.Argument(..., help="Search query (e.g., 'vulnerability research', 'filetype:pdf')."),
    cse_id: str = typer.Option(..., "--cse-id", help="Google Custom Search Engine ID."),
    limit: int = typer.Option(10, help="Number of results to retrieve (max 10 per query)."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """
    Search academic portals, journals, and databases using Google CSE.
    """
    console.print(f"[cyan]Searching deep web portals with CSE ID: {cse_id}[/cyan]")
    console.print(f"[cyan]Query:[/cyan] {query}")

    with console.status("[spinner]Querying custom search engine..."):
        results_model = search_deep_web(query, cse_id, num_results=limit)
    
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)

    console.print(f"[green]Found {results_model.total_results} total results. Showing {len(results_model.hits)}.[/green]")
    
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    
    save_scan_to_db(
        target=query,
        module="deep_web_analyzer",
        data=results_dict
    )