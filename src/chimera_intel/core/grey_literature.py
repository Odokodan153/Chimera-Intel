"""
Module for Grey Literature Intelligence (GREYINT).

Provides tools to search for and retrieve grey literature, such as technical reports,
white papers, pre-prints, and official documents, using targeted search engine queries.
"""

import typer
import logging
from typing import Optional, List, Dict, Any
from .schemas import BaseModel, Field
from .http_client import sync_client
from .utils import save_or_print_results, console
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)

# --- Pydantic Schemas ---

class GreyLitResult(BaseModel):
    """A single piece of grey literature found."""
    title: str = Field(..., description="The title of the document.")
    url: str = Field(..., description="The direct URL to the document.")
    source_domain: str = Field(..., description="The domain the document was found on.")
    snippet: str = Field(..., description="A snippet of text from the document.")
    file_type: str = Field(..., description="The detected file type (e.g., PDF, DOCX).")

class GreyLitOverallResult(BaseModel):
    """The overall result of a grey literature search."""
    query: str
    total_results: int
    results: List[GreyLitResult]
    error: Optional[str] = None

# --- Core Function ---

def search_grey_literature(
    query: str,
    file_types: List[str] = ["pdf"],
    domains: List[str] = ["org", "gov", "edu", "mil"],
) -> GreyLitOverallResult:
    """
    Searches for grey literature using the Google Custom Search API.
    """
    api_key = API_KEYS.get("google_api_key")
    cse_id = API_KEYS.get("google_cse_id")

    if not api_key or not cse_id:
        msg = "GOOGLE_API_KEY and GOOGLE_CSE_ID must be set in config."
        logger.warning(msg)
        return GreyLitOverallResult(query=query, total_results=0, results=[], error=msg)

    search_url = "https://www.googleapis.com/customsearch/v1"
    
    # Construct a powerful search query
    # Example: "supply chain" filetype:pdf (site:.org OR site:.gov)
    file_query = " OR ".join([f"filetype:{ft}" for ft in file_types])
    domain_query = " OR ".join([f"site:.{dom}" for dom in domains])
    full_query = f"{query} {file_query} ({domain_query})"

    params = {
        "key": api_key,
        "cx": cse_id,
        "q": full_query,
        "num": 10,  # Max 10 results per query
    }

    try:
        response = sync_client.get(search_url, params=params)
        response.raise_for_status()
        data = response.json()

        items = data.get("items", [])
        search_results: List[GreyLitResult] = []

        for item in items:
            file_format = item.get("fileFormat", "Unknown")
            # Ensure it's a file type we were looking for
            if any(ft.lower() in file_format.lower() for ft in file_types):
                search_results.append(
                    GreyLitResult(
                        title=item.get("title", "No Title"),
                        url=item.get("link"),
                        source_domain=item.get("displayLink", "Unknown Domain"),
                        snippet=item.get("snippet", "No Snippet"),
                        file_type=file_format,
                    )
                )

        return GreyLitOverallResult(
            query=full_query,
            total_results=len(search_results),
            results=search_results,
        )

    except Exception as e:
        logger.error(f"Failed to query Google Custom Search API: {e}")
        return GreyLitOverallResult(
            query=full_query, total_results=0, results=[], error=f"An API error occurred: {e}"
        )

# --- Typer CLI Application ---

grey_lit_app = typer.Typer(
    name="grey-lit",
    help="Search for Grey Literature (reports, white papers, etc.)."
)

@grey_lit_app.command("search")
def run_grey_lit_search(
    query: str = typer.Argument(..., help="The search query (e.g., 'supply chain risk')."),
    file_types: Optional[List[str]] = typer.Option(
        ["pdf", "pptx"], "--filetype", "-f", help="File types to search for."
    ),
    domains: Optional[List[str]] = typer.Option(
        ["org", "gov", "edu"], "--domain", "-d", help="Domain extensions to target (e.g., org, gov)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Searches for grey literature on specific domain types.
    """
    console.print(f"[bold cyan]Searching for grey literature matching '{query}'...[/bold cyan]")
    
    # Ensure non-empty lists if provided
    ft = file_types if file_types else ["pdf"]
    doms = domains if domains else ["org", "gov", "edu"]

    results_model = search_grey_literature(query, file_types=ft, domains=doms)
    results_dict = results_model.model_dump(exclude_none=True)
    
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)

    console.print(f"[green]Found {results_model.total_results} relevant documents.[/green]")
    save_or_print_results(results_dict, output_file, print_to_console=False)

    if not output_file:
        # Print a summary table if not saving to file
        for res in results_model.results:
            console.print(f"\n[bold]{res.title}[/bold] ({res.file_type})")
            console.print(f"  [cyan]{res.source_domain}[/cyan]")
            console.print(f"  [dim]{res.url}[/dim]")