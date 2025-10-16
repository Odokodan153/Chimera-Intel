"""
Module for Legal Intelligence (LEGINT).

Handles the gathering of intelligence from legal sources, such as court dockets
and case filings, to provide insights into a company's litigation history.
"""

import typer
import logging
from typing import Optional
from .schemas import DocketSearchResult, CourtRecord
from .utils import save_or_print_results
from .database import save_scan_to_db
from .config_loader import API_KEYS
from .http_client import sync_client
from .project_manager import resolve_target

logger = logging.getLogger(__name__)


def search_court_dockets(company_name: str) -> DocketSearchResult:
    """
    Searches for court dockets related to a company name using the CourtListener API.

    Args:
        company_name (str): The name of the company to search for in court records.

    Returns:
        DocketSearchResult: A Pydantic model with the search results.
    """
    api_key = API_KEYS.courtlistener_api_key
    if not api_key:
        return DocketSearchResult(
            query=company_name,
            error="CourtListener API key not found in .env file.",
        )
    logger.info(f"Searching CourtListener for dockets related to: {company_name}")

    base_url = "https://www.courtlistener.com/api/rest/v3/search/"
    headers = {"Authorization": f"Token {api_key}"}
    params = {
        "q": company_name,
        "type": "d",
        "order_by": "dateFiled desc",
    }  # d = dockets

    try:
        response = sync_client.get(base_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        records = [CourtRecord.model_validate(rec) for rec in data.get("results", [])]

        return DocketSearchResult(
            query=company_name,
            total_found=data.get("count", 0),
            records=records,
        )
    except Exception as e:
        logger.error(f"Failed to get court dockets for {company_name}: {e}")
        return DocketSearchResult(
            query=company_name, error=f"An API error occurred: {e}"
        )


# --- Typer CLI Application ---


legint_app = typer.Typer()


@legint_app.command("docket-search")
def run_docket_search(
    company_name: Optional[str] = typer.Option(
        None,
        "--company-name",
        "-n",
        help="The company name to search. Uses active project if not provided.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Searches court records for dockets related to a company."""
    try:
        target_company = resolve_target(company_name, required_assets=["company_name"])

        results_model = search_court_dockets(target_company)
        if results_model.error:
            typer.echo(f"Error: {results_model.error}", err=True)
            raise typer.Exit(code=1)
        results_dict = results_model.model_dump(exclude_none=True, by_alias=True)
        save_or_print_results(results_dict, output_file)
        save_scan_to_db(
            target=target_company, module="legint_docket_search", data=results_dict
        )
    except Exception as e:
        # Catch any other unexpected errors

        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)
