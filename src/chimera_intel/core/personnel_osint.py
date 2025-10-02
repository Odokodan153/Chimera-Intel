import typer
import logging
from typing import Dict, Union, Optional
from .schemas import PersonnelOSINTResult, EmployeeProfile
from .config_loader import API_KEYS
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
