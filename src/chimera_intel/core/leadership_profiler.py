"""
Module for Deep Leadership (HUMINT/OSINT) Profiling.

Performs deep-dive OSINT on key executives to identify vulnerabilities,
undisclosed affiliations, and potential insider threats.
"""

import typer
import logging
from typing import Optional, List, Dict, Any
from .schemas import LeadershipProfileResult, ExecutiveFinding
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .project_manager import resolve_target, get_active_project
from .ai_core import generate_swot_from_data
from .google_search import run_google_search
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)

leadership_profiler_app = typer.Typer(
    name="leadership-profiler",
    help="Deep-dive OSINT/HUMINT on key executives."
)


def profile_leadership(person_name: str, company_name: str) -> LeadershipProfileResult:
    """
    Generates a deep-dive profile on a key executive.

    Args:
        person_name (str): The full name of the executive.
        company_name (str): The name of their primary company.

    Returns:
        LeadershipProfileResult: A Pydantic model with the findings.
    """
    logger.info(f"Profiling executive {person_name} from {company_name}")
    
    # 1. Gather OSINT (Philanthropy, Political Donations, Alumni Networks)
    queries = [
        f'"{person_name}" "{company_name}" political donations',
        f'"{person_name}" "{company_name}" philanthropy OR foundation',
        f'"{person_name}" alumni OR "board of directors" -"{company_name}"',
        f'"{person_name}" vulnerabilities OR "insider threat" OR "conflict of interest"',
    ]
    
    search_results = run_google_search(queries, num_results=5)
    
    if not search_results.results:
        return LeadershipProfileResult(
            person_name=person_name,
            error="No public OSINT data found for this individual.",
        )

    # 2. Synthesize OSINT data for AI Analysis
    snippets = [
        f"Source: {res.get('url', 'N/A')}\nSnippet: {res.get('snippet', 'N/A')}"
        for res in search_results.results
    ]
    full_text = "\n---\n".join(snippets)

    # 3. Use AI core to identify vulnerabilities and affiliations
    api_key = API_KEYS.google_api_key
    if not api_key:
        return LeadershipProfileResult(
            person_name=person_name, error="Google API key not configured."
        )

    prompt = f"""
    As a HUMINT and strategic intelligence analyst, analyze the following OSINT search results for the executive '{person_name}' of '{company_name}'.
    Your goal is to identify potential vulnerabilities, undisclosed affiliations, and conflicts of interest.

    Look for:
    1.  **Undisclosed Affiliations**: Connections to other companies, boards, or political groups not immediately obvious.
    2.  **Potential Vulnerabilities**: Information related to financial distress, strong political leanings, questionable associations, or public grievances.
    3.  **Insider Threat Indicators**: Any language suggesting disillusionment or conflict with their current company (this is rare in public data).
    4.  **Network Mapping**: Key connections (alumni, philanthropy, political) that could be used for influence or elicitation.

    **OSINT Data:**
    {full_text[:4000]}

    Return a concise summary of findings, highlighting actionable intelligence.
    """

    ai_result = generate_swot_from_data(prompt, api_key)
    
    if ai_result.error:
        return LeadershipProfileResult(
            person_name=person_name, error=f"AI analysis failed: {ai_result.error}"
        )

    # Dummy data for structured fields
    findings = [
        ExecutiveFinding(
            finding_type="Vulnerability",
            description="Extracted from AI (e.g., 'Strong public political donations to one party')",
            source_snippet="Extracted from AI"
        ),
        ExecutiveFinding(
            finding_type="Affiliation",
            description="Extracted from AI (e.g., 'Sits on the board of TechForGood NGO')",
            source_snippet="Extracted from AI"
        ),
    ]

    return LeadershipProfileResult(
        person_name=person_name,
        company=company_name,
        analysis_summary=ai_result.analysis_text,
        findings=findings,
    )


@leadership_profiler_app.command("run")
def run_leadership_profile(
    person_name: str = typer.Option(
        ..., "--person", "-p", help="The full name of the executive to profile."
    ),
    company_name: Optional[str] = typer.Option(
        None, "--company", "-c", help="The executive's company. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Profiles a key executive for vulnerabilities and hidden affiliations.
    """
    target_company = company_name
    if not target_company:
        active_project = get_active_project()
        if active_project and active_project.company_name:
            target_company = active_project.company_name
            console.print(
                f"[bold cyan]Using company name '{target_company}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No company name provided and no active project with a company name is set."
            )
            raise typer.Exit(code=1)
    
    if not target_company:
         console.print(
            "[bold red]Error:[/bold red] A company name is required, either via --company or an active project."
        )
         raise typer.Exit(code=1)

    with console.status(
        f"[bold cyan]Profiling executive {person_name} at {target_company}...[/bold cyan]"
    ):
        results_model = profile_leadership(person_name, target_company)
    
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=f"{person_name}@{target_company}",
        module="corporate_leadership_profile",
        data=results_dict
    )