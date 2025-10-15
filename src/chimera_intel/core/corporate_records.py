import typer
import logging
import os
from bs4 import BeautifulSoup, Tag, ResultSet
from typing import Set, Optional
from .schemas import (
    CorporateRegistryResult,
    CompanyRecord,
    Officer,
    SanctionsScreeningResult,
    SanctionedEntity,
    PEPScreeningResult,
)
from .config_loader import API_KEYS
from .http_client import sync_client
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .project_manager import resolve_target


logger = logging.getLogger(__name__)

# --- Dynamic PEP List Handling ---


PEP_DATA_URL = "https://datasets.opensanctions.org/datasets/latest/peps/names.txt"
PEP_FILE_PATH = "pep_list.txt"
PEP_LIST_CACHE: Set[str] = set()


def load_pep_list() -> Set[str]:
    """
    Loads the PEP list from a local file, downloading it if necessary.
    Uses an in-memory cache to avoid reading the file on every call.
    """
    global PEP_LIST_CACHE
    if PEP_LIST_CACHE:
        return PEP_LIST_CACHE
    if not os.path.exists(PEP_FILE_PATH):
        logger.info(f"Local PEP list not found. Downloading from {PEP_DATA_URL}...")
        try:
            response = sync_client.get(PEP_DATA_URL, follow_redirects=True)
            response.raise_for_status()
            pep_text = response.text
            with open(PEP_FILE_PATH, "w", encoding="utf-8") as f:
                f.write(pep_text)
            logger.info("Successfully downloaded PEP list.")
            pep_set = {line.strip().upper() for line in pep_text.splitlines()}
            PEP_LIST_CACHE.update(pep_set)
            return PEP_LIST_CACHE
        except Exception as e:
            logger.error(f"Failed to download PEP list: {e}")
            return set()
    try:
        with open(PEP_FILE_PATH, "r", encoding="utf-8") as f:
            # Use a set for efficient lookups

            pep_set = {line.strip().upper() for line in f}
            PEP_LIST_CACHE.update(pep_set)
        return PEP_LIST_CACHE
    except Exception as e:
        logger.error(f"Failed to read PEP list file: {e}")
        return set()


def get_company_records(company_name: str) -> CorporateRegistryResult:
    """
    Retrieves official company records from the OpenCorporates API.

    Args:
        company_name (str): The company name to search for.

    Returns:
        CorporateRegistryResult: A Pydantic model with the company records, or an error.
    """
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
        results = data.get("results", {})
        if results:
            companies = results.get("companies", [])
            for item in companies:
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
                total_found=results.get("total_count", 0),
                records=records,
            )
        else:
            return CorporateRegistryResult(
                query=company_name,
                total_found=0,
                records=records,
            )
    except Exception as e:
        logger.error("Error querying OpenCorporates for '%s': %s", company_name, e)
        return CorporateRegistryResult(
            query=company_name, error=f"An API error occurred: {e}"
        )


def screen_sanctions_list(name: str) -> SanctionsScreeningResult:
    """
    Screens a name against the U.S. Treasury's OFAC Sanctions List.

    Args:
        name (str): The name of the individual or entity to screen.

    Returns:
        SanctionsScreeningResult: A Pydantic model with any potential matches.
    """
    logger.info("Screening name '%s' against OFAC sanctions list.", name)
    url = "https://sanctionssearch.ofac.treas.gov/Details.aspx"
    params = {"ss": name, "type": "All"}

    try:
        response = sync_client.get(url, params=params)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        results_table = soup.find("table", {"class": "table-bordered"})
        if not isinstance(results_table, Tag):
            return SanctionsScreeningResult(query=name, hits_found=0)
        tbody = results_table.find("tbody")
        if not isinstance(tbody, Tag):
            return SanctionsScreeningResult(query=name, hits_found=0)
        entities = []
        rows: ResultSet = tbody.find_all("tr")
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


def screen_pep_list(name: str) -> PEPScreeningResult:
    """
    Screens a name against a list of Politically Exposed Persons (PEPs).

    Args:
        name (str): The name of the individual to screen.

    Returns:
        PEPScreeningResult: A Pydantic model indicating if the name is a PEP.
    """
    pep_list = load_pep_list()
    is_pep = name.upper() in pep_list
    return PEPScreeningResult(query=name, is_pep=is_pep)


# --- Typer CLI Application ---


corporate_records_app = typer.Typer()


@corporate_records_app.command("registry")
def run_registry_search(
    company: Optional[str] = typer.Argument(
        None, help="The company name to search. Uses active project if not provided."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Searches official company registries for a given company name."""
    target_company = resolve_target(company, required_assets=["company_name"])

    results_model = get_company_records(target_company)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_company, module="corporate_registry", data=results_dict
    )


@corporate_records_app.command("sanctions")
def run_sanctions_screening(
    name: Optional[str] = typer.Argument(
        None,
        help="The name to screen. Uses active project's company name if not provided.",
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Screens a name against the OFAC sanctions and watchlists."""
    target_name = resolve_target(name, required_assets=["company_name"])

    results_model = screen_sanctions_list(target_name)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_name, module="corporate_sanctions_screen", data=results_dict
    )


@corporate_records_app.command("pep")
def run_pep_screening(
    name: Optional[str] = typer.Argument(
        None,
        help="The name to screen. Uses active project's company name if not provided.",
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Screens a name against a Politically Exposed Persons (PEP) list."""
    target_name = resolve_target(name, required_assets=["company_name"])

    results_model = screen_pep_list(target_name)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_name, module="corporate_pep_screen", data=results_dict
    )
