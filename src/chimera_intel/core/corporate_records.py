import typer
import logging
from bs4 import BeautifulSoup
from .schemas import (
    CorporateRegistryResult,
    CompanyRecord,
    Officer,
    SanctionsScreeningResult,
    SanctionedEntity,  # <-- ADDED IMPORTS
)
from .config_loader import API_KEYS
from .http_client import sync_client
from .utils import save_or_print_results, console  # <-- ADDED console
from .database import save_scan_to_db

logger = logging.getLogger(__name__)

# --- Company Registry Function (remains the same) ---


def get_company_records(company_name: str) -> CorporateRegistryResult:
    # ... (this function is unchanged)

    api_key = API_KEYS.open_corporates_api_key
    if not api_key:
        return CorporateRegistryResult(
            query=company_name, error="OpenCorporates API key not found."
        )
    url = "https://api.opencorporates.com/v0.4/companies/search"
    params = {"q": company_name, "api_token": api_key}

    try:
        response = sync_client.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        records = []
        results = data.get("results", {}).get("companies", [])
        for item in results:
            company_data = item.get("company", {})
            officers = [
                Officer(
                    name=officer.get("officer", {}).get("name"),
                    position=officer.get("officer", {}).get("position"),
                )
                for officer in company_data.get("officers", [])
            ]
            address = company_data.get("registered_address_in_full")
            record = CompanyRecord(
                name=company_data.get("name"),
                company_number=company_data.get("company_number"),
                jurisdiction=company_data.get("jurisdiction_code"),
                registered_address=address,
                is_inactive=company_data.get("inactive"),
                officers=officers,
            )
            records.append(record)
        return CorporateRegistryResult(
            query=company_name,
            total_found=data.get("results", {}).get("total_count", 0),
            records=records,
        )
    except Exception as e:
        logger.error("Error querying OpenCorporates for '%s': %s", company_name, e)
        return CorporateRegistryResult(
            query=company_name, error=f"An API error occurred: {e}"
        )


# --- NEW SANCTIONS SCREENING FUNCTION ---


def screen_sanctions_list(name: str) -> SanctionsScreeningResult:
    """
    Screens a name against the U.S. Treasury's OFAC Sanctions List.

    Args:
        name (str): The name of the individual or entity to screen.

    Returns:
        SanctionsScreeningResult: A Pydantic model with any potential matches.
    """
    logger.info("Screening name '%s' against OFAC sanctions list.", name)
    # This URL structure is based on the official OFAC search tool

    url = "https://sanctionssearch.ofac.treas.gov/Details.aspx"
    params = {"ss": name, "type": "All"}

    try:
        response = sync_client.get(url, params=params)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        results_table = soup.find("table", {"class": "table-bordered"})
        if not results_table:
            return SanctionsScreeningResult(query=name, hits_found=0)
        entities = []
        rows = results_table.find("tbody").find_all("tr")
        for row in rows:
            cells = row.find_all("td")
            if len(cells) == 5:
                entity = SanctionedEntity(
                    name=cells[0].text.strip(),
                    address=cells[1].text.strip(),
                    type=cells[2].text.strip(),
                    programs=[p.strip() for p in cells[3].text.strip().split(",")],
                    score=int(cells[4].text.strip()),
                )
                entities.append(entity)
        return SanctionsScreeningResult(
            query=name, hits_found=len(entities), entities=entities
        )
    except Exception as e:
        logger.error("Error scraping OFAC sanctions list for '%s': %s", name, e)
        return SanctionsScreeningResult(
            query=name, error=f"An error occurred during screening: {e}"
        )


# --- Typer CLI Application ---

corporate_records_app = typer.Typer()


@corporate_records_app.command("registry")
def run_registry_search(
    company: str = typer.Argument(
        ..., help="The company name to search in the corporate registry."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Searches official company registries for a given company name."""
    with console.status(
        f"[bold cyan]Searching corporate registry for '{company}'...[/bold cyan]"
    ):
        results_model = get_company_records(company)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=company, module="corporate_registry", data=results_dict)


# --- NEW SCREENING COMMAND ---


@corporate_records_app.command("screen")
def run_sanctions_screening(
    name: str = typer.Argument(
        ..., help="The name of the individual or entity to screen."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Screens a name against the OFAC sanctions and watchlists."""
    with console.status(
        f"[bold cyan]Screening '{name}' against sanctions lists...[/bold cyan]"
    ):
        results_model = screen_sanctions_list(name)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    # Note: We might not want to save every single screening to the DB unless it's a primary target.
    # For now, we'll just print/save the output.
