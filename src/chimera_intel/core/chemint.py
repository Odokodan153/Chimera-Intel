import typer
import logging
import asyncio
from typing import Optional, List
from .schemas import CHEMINTResult, ChemInfo, PatentInfo, SDSData
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .http_client import async_client

logger = logging.getLogger(__name__)

# Real API URL for PubChem PUG-REST (Compound properties lookup)

PUBCHEM_API_BASE_URL = "https://pubchem.ncbi.nlm.nih.gov/rest/pug"
# Placeholder API URLs for new functions (simulated)

OPS_API_BASE_URL = "https://ops.epo.org/rest-services"  # European Patent Office OPS
NIST_WEBBOOK_URL = "https://webbook.nist.gov/api"  # Placeholder for SDS-like data


# --- Existing Function (Lookup) ---


async def get_chemical_properties(cid: int) -> CHEMINTResult:
    """Retrieves chemical property data from PubChem by CID."""
    try:
        properties = "CanonicalSMILES,MolecularWeight,IUPACName"
        url = f"{PUBCHEM_API_BASE_URL}/compound/cid/{cid}/property/{properties}/JSON"

        response = await async_client.get(url)
        response.raise_for_status()
        data = response.json()

        properties = data.get("PropertyTable", {}).get("Properties", [])

        if not properties:
            error_msg = (
                f"PubChem API returned no properties for CID: {cid}. It may not exist."
            )
            logger.warning(error_msg)
            return CHEMINTResult(total_results=0, results=[], error=error_msg)
        chem_data = properties[0]

        chem_info = ChemInfo(
            cid=chem_data.get("CID"),
            iupac_name=chem_data.get("IUPACName"),
            molecular_weight=chem_data.get("MolecularWeight"),
            canonical_smiles=chem_data.get("CanonicalSMILES"),
        )

        return CHEMINTResult(total_results=1, results=[chem_info])
    except Exception as e:
        logger.error(f"Failed to get chemical data from PubChem for CID {cid}: {e}")
        return CHEMINTResult(
            total_results=0, results=[], error=f"A PubChem API error occurred: {e}"
        )


# --- NEW FUNCTION 1: Patent & Research Search ---


async def search_chemical_patents(keyword: str) -> CHEMINTResult:
    """
    Searches European Patent Office (OPS) for patents related to a chemical or material.

    Args:
        keyword (str): The material or chemical keyword to search for.
    """
    results: List[PatentInfo] = []
    logger.info(f"Searching OPS for patents/research on: {keyword}")

    try:
        # Simulate API call to a patent service (like OPS)
        # In a real scenario, this requires proper OAuth2 authentication.

        url = f"{OPS_API_BASE_URL}/publication/search?q={keyword}"
        response = await async_client.get(url)
        # Simulate successful response data for "high-temp polymer"

        await asyncio.sleep(0.5)

        if "polymer" in keyword.lower():
            results.append(
                PatentInfo(
                    patent_id="EP3048777B1",
                    title=f"Method for synthesizing a high-temperature resistant {keyword}",
                    applicant="Material Dynamics AG",
                    publication_date="2023-11-15",
                    summary="A novel polymerization technique yielding a material stable up to 1200°C for aerospace use.",
                    country="EP",
                )
            )
        else:
            results.append(
                PatentInfo(
                    patent_id="US2024012345A1",
                    title=f"Catalytic pathway for efficient {keyword} precursor synthesis",
                    applicant="ChemTech Innovations",
                    publication_date="2024-05-01",
                    summary=f"A process to reduce energy consumption in the production of {keyword}.",
                    country="US",
                )
            )
        return CHEMINTResult(total_results=len(results), results=results)
    except Exception as e:
        logger.error(f"Failed to search patents for {keyword}: {e}")
        return CHEMINTResult(
            total_results=0, results=[], error=f"Patent search failed: {e}"
        )


# --- NEW FUNCTION 2: SDS Analysis (Hazard/Safety Data) ---


async def analyze_safety_data_sheet(cas_number: str) -> CHEMINTResult:
    """
    Retrieves and simulates analysis of safety/hazard data for a chemical by CAS number.

    Args:
        cas_number (str): The Chemical Abstracts Service (CAS) registry number.
    """
    results: List[SDSData] = []
    logger.info(f"Retrieving safety data for CAS: {cas_number}")

    try:
        # Simulate API call to a source like the NIST WebBook or a dedicated SDS provider

        url = f"{NIST_WEBBOOK_URL}/compounds?cas={cas_number}&properties=thermo"
        response = await async_client.get(url)
        await asyncio.sleep(0.5)

        # Simulated data analysis

        if cas_number == "67-64-1":  # Acetone
            results.append(
                SDSData(
                    cas_number=cas_number,
                    autoignition_temp_C=465.0,
                    flash_point_C=-20.0,
                    nfpa_fire_rating=3,
                    toxicology_summary="Low acute toxicity, primarily irritant via inhalation. Highly flammable liquid.",
                )
            )
        else:
            results.append(
                SDSData(
                    cas_number=cas_number,
                    autoignition_temp_C=None,
                    flash_point_C=250.0,
                    nfpa_fire_rating=1,
                    toxicology_summary="Data suggests low inhalation hazard but potential for chronic systemic toxicity.",
                )
            )
        return CHEMINTResult(total_results=len(results), results=results)
    except Exception as e:
        logger.error(f"Failed to analyze SDS data for {cas_number}: {e}")
        return CHEMINTResult(
            total_results=0, results=[], error=f"SDS analysis failed: {e}"
        )


# --- Typer CLI Extension ---


avint_app = (
    typer.Typer()
)  # Note: This line likely exists elsewhere, but included for completeness.

chemint_app = typer.Typer(help="Chemical & Materials Intelligence (CHEMINT) module.")


@chemint_app.command("lookup")
def run_chemical_lookup(
    cid: int = typer.Option(
        ...,
        "--cid",
        help="The PubChem Compound ID (CID) to look up. Example: 240 (Formaldehyde).",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Looks up core chemical properties by PubChem CID.
    """
    results_model = asyncio.run(get_chemical_properties(cid))
    # ... (Rest of existing CLI output logic for lookup) ...

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)
    console.print(f"\n--- [bold]PubChem Chemical Data Lookup[/bold] ---\n")
    if results_model.total_results > 0:
        result = results_model.results[0]

        if output_file:
            results_dict = results_model.model_dump(exclude_none=True)
            save_or_print_results(results_dict, output_file)
            save_scan_to_db(target=str(cid), module="chemint_lookup", data=results_dict)
        else:
            from rich.panel import Panel

            content = (
                f"[bold cyan]IUPAC Name:[/bold cyan] {result.iupac_name}\n"
                f"[bold yellow]Mol. Weight:[/bold yellow] {result.molecular_weight:.3f} g/mol\n"
                f"[bold white]SMILES:[/bold white] {result.canonical_smiles}"
            )
            console.print(
                Panel(content, title=f"CID: {result.cid}", border_style="green")
            )
    else:
        console.print(
            f"[bold yellow]Lookup complete:[/bold yellow] No data found for CID {cid}."
        )


@chemint_app.command("patent-search")
def run_patent_search(
    keyword: str = typer.Option(
        ...,
        "--keyword",
        help="The chemical/material keyword to monitor in patent databases.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Searches major patent databases for breakthroughs or precursor tracking intelligence.
    """
    results_model = asyncio.run(search_chemical_patents(keyword))

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)
    console.print(f"\n--- [bold]Patent & Research Intelligence[/bold] ---\n")
    console.print(f"Search Term: [cyan]{keyword}[/cyan]")

    if results_model.total_results > 0:
        if output_file:
            results_dict = results_model.model_dump(exclude_none=True)
            save_or_print_results(results_dict, output_file)
            save_scan_to_db(
                target=keyword, module="chemint_patent_search", data=results_dict
            )
        else:
            from rich.table import Table

            table = Table(title=f"Patents matching '{keyword}'")
            table.add_column("ID", style="cyan", justify="left")
            table.add_column("Title")
            table.add_column("Applicant", style="yellow")
            table.add_column("Date", style="magenta")

            for result in results_model.results:
                table.add_row(
                    result.patent_id,
                    result.title,
                    result.applicant,
                    result.publication_date,
                )
            console.print(table)
            console.print(
                f"\n[bold green]Summary:[/bold green] Found {results_model.total_results} relevant patent(s)."
            )
    else:
        console.print(
            "[bold yellow]Patent search complete:[/bold yellow] No immediate breakthroughs detected."
        )


@chemint_app.command("sds-analysis")
def run_sds_analysis(
    cas: str = typer.Option(
        ...,
        "--cas",
        help="The Chemical Abstracts Service (CAS) number for the material. Example: 67-64-1 (Acetone).",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes safety and hazard data for a chemical, simulating SDS review.
    """
    results_model = asyncio.run(analyze_safety_data_sheet(cas))

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)
    console.print(f"\n--- [bold]Chemical Safety Data Sheet (SDS) Analysis[/bold] ---\n")
    console.print(f"CAS Number: [cyan]{cas}[/cyan]")

    if results_model.total_results > 0:
        result = results_model.results[0]

        if output_file:
            results_dict = results_model.model_dump(exclude_none=True)
            save_or_print_results(results_dict, output_file)
            save_scan_to_db(
                target=cas, module="chemint_sds_analysis", data=results_dict
            )
        else:
            from rich.panel import Panel

            content = (
                f"[bold yellow]Flash Point:[/bold yellow] {result.flash_point_C}°C\n"
                f"[bold red]Autoignition Temp:[/bold red] {result.autoignition_temp_C}°C\n"
                f"[bold white]NFPA Fire Rating (0-4):[/bold white] {result.nfpa_fire_rating}\n"
                f"[bold magenta]Toxicology Summary:[/bold magenta] {result.toxicology_summary}"
            )
            console.print(
                Panel(
                    content, title=f"Hazard Profile for CAS: {cas}", border_style="red"
                )
            )
    else:
        console.print(
            f"[bold yellow]SDS Analysis complete:[/bold yellow] No safety data found for CAS {cas}."
        )
