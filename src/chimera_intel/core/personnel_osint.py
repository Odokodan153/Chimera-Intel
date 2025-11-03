import typer
import logging
from typing import Dict, Union, Optional, List
from .schemas import PersonnelOSINTResult, EmployeeProfile, SocialProfile
from .config_loader import API_KEYS
import asyncio
from .google_search import search_google
from .http_client import sync_client
from .utils import save_or_print_results, is_valid_domain, console
from .database import save_scan_to_db
from rich.panel import Panel
from .project_manager import get_active_project

logger = logging.getLogger(__name__)


def find_employee_emails(domain: str) -> PersonnelOSINTResult:
    """
    Finds employee email addresses for a given domain using the Hunter.io API.

    Args:
        domain (str): The domain to search for.

    Returns:
        PersonnelOSINTResult: A Pydantic model containing the results.
    """
    api_key = API_KEYS.hunter_api_key
    if not api_key:
        return PersonnelOSINTResult(
            domain=domain, error="Hunter.io API key not found in .env file."
        )
    url = "https://api.hunter.io/v2/domain-search"
    params: Dict[str, Union[str, int]] = {
        "domain": domain,
        "api_key": api_key,
        "limit": 100,
    }

    try:
        response = sync_client.get(url, params=params)
        if response.status_code == 401:  # Specific check for invalid API key
            return PersonnelOSINTResult(
                domain=domain, error="Invalid Hunter.io API key."
            )
        response.raise_for_status()

        data = response.json().get("data", {})

        # FIX: Map the 'value' field from the API to the 'email' field in the Pydantic model.

        profiles = [
            EmployeeProfile(email=email_info.pop("value"), **email_info)
            for email_info in data.get("emails", [])
        ]

        return PersonnelOSINTResult(
            domain=domain,
            organization_name=data.get("organization"),
            total_emails_found=len(profiles),
            employee_profiles=profiles,
        )
    except Exception as e:
        logger.error(
            "An error occurred while querying Hunter.io for domain '%s': %s", domain, e
        )
        return PersonnelOSINTResult(
            domain=domain, error=f"An unexpected error occurred: {e}"
        )
    
async def find_linkedin_profiles(
    company_name: str, employee_profiles: List[EmployeeProfile]
) -> List[SocialProfile]:
    """
    Finds LinkedIn profiles for known employees using Google Dorking.

    This function leverages the existing Google Search module to find public
    LinkedIn profiles matching employee names and the company.

    Args:
        company_name (str): The name of the company.
        employee_profiles (List[EmployeeProfile]): A list of employees from Hunter.io.

    Returns:
        List[SocialProfile]: A list of potential LinkedIn profiles.
    """
    logger.info(
        f"Attempting to find LinkedIn profiles for {company_name} via Google Dorking"
    )
    found_profiles: List[SocialProfile] = []

    api_key = API_KEYS.google_api_key
    cse_id = API_KEYS.google_cse_id

    if not api_key or not cse_id:
        logger.warning(
            "Google API key or CSE ID not found. Skipping LinkedIn enrichment."
        )
        return []

    tasks = []
    for profile in employee_profiles:
        if profile.first_name and profile.last_name:
            name = f"{profile.first_name} {profile.last_name}"
            # Create a specific Google Dork query
            query = f'"{name}" "{company_name}" site:linkedin.com/in'
            # Search for just the top 1 result per employee
            tasks.append(search_google(query, api_key, cse_id, num_results=1))

    try:
        search_results_list = await asyncio.gather(*tasks)
    except Exception as e:
        logger.error(f"Error during Google search for LinkedIn profiles: {e}")
        return []

    for google_result in search_results_list:
        if google_result.items:
            # Take the first item from the Google search
            item = google_result.items[0]
            profile_name = item.get("title", "Unknown Name").split(" - ")[
                0
            ]  # Clean up title
            found_profiles.append(
                SocialProfile(
                    name=profile_name, url=item.get("link", "Unknown URL")
                )
            )

    logger.info(
        f"Found {len(found_profiles)} potential LinkedIn profiles via Google."
    )
    return found_profiles

# --- Typer CLI Application ---


personnel_osint_app = typer.Typer()


@personnel_osint_app.command("emails")
def run_email_search(
    domain: Optional[str] = typer.Argument(
        None, help="The domain to search for. Uses active project if not provided."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Searches for public employee email addresses for a given domain.
    """
    target_domain = domain
    if not target_domain:
        active_project = get_active_project()
        if active_project and active_project.domain:
            target_domain = active_project.domain
            console.print(
                f"[bold cyan]Using domain '{target_domain}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No domain provided and no active project set. Use 'chimera project use <name>' or specify a domain."
            )
            raise typer.Exit(code=1)
    if not is_valid_domain(target_domain):
        logger.warning(
            "Invalid domain format provided to 'personnel' command: %s", target_domain
        )
        console.print(
            Panel(
                f"[bold red]Invalid Input:[/] '{target_domain}' is not a valid domain format.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    with console.status(
        f"[bold cyan]Searching for emails at {target_domain}...[/bold cyan]"
    ):
        results_model = find_employee_emails(target_domain)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_domain, module="personnel_osint_emails", data=results_dict
    )
    logger.info("Email search complete for domain: %s", target_domain)

@personnel_osint_app.command("enrich")
def run_personnel_enrichment(
    domain: Optional[str] = typer.Argument(
        None, help="The domain to search for. Uses active project if not provided."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Finds emails and enriches them with potential LinkedIn profiles.
    """
    target_domain = domain
    active_project = get_active_project()
    if not target_domain:
        if active_project and active_project.domain:
            target_domain = active_project.domain
            console.print(
                f"[bold cyan]Using domain '{target_domain}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No domain provided and no active project set."
            )
            raise typer.Exit(code=1)

    with console.status(
        f"[bold cyan]Searching for emails at {target_domain}...[/bold cyan]"
    ):
        email_results = find_employee_emails(target_domain)

    if email_results.error:
        console.print(f"[bold red]Email search failed:[/bold red] {email_results.error}")
        raise typer.Exit(code=1)

    console.print(f"Found {email_results.total_emails_found} emails.")

    company_name = (
        email_results.organization_name
        or (active_project.company_name if active_project else None)
        or target_domain
    )

    if not email_results.employee_profiles:
        console.print("[bold yellow]No employee profiles found to enrich.[/bold yellow]")
        return

    with console.status(
        f"[bold cyan]Enriching {len(email_results.employee_profiles)} employees with LinkedIn data...[/bold cyan]"
    ):
        # Run the new async function
        linkedin_results = asyncio.run(
            find_linkedin_profiles(company_name, email_results.employee_profiles)
        )

    console.print(f"Found {len(linkedin_results)} potential LinkedIn profiles.")

    # Combine results for output
    combined_results = {
        "email_search": email_results.model_dump(exclude_none=True),
        "linkedin_enrichment": [p.model_dump() for p in linkedin_results],
    }

    save_or_print_results(combined_results, output_file)
    save_scan_to_db(
        target=target_domain, module="personnel_osint_enrich", data=combined_results
    )
