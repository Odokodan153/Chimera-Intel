"""
Ultimate Strategic Deep Research & Intelligence Fusion Module for Chimera Intel.

This module represents the pinnacle of automated OSINT analysis, fusing a wide
spectrum of intelligence disciplines into a single, coherent strategic picture.
It also includes the Typer-based CLI for user interaction.
"""

import asyncio
import json
import logging
import typer
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.pretty import pprint
from typing import List, Dict, Any, Optional
import google.generativeai as genai
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.google_search import search
from chimera_intel.core.schemas import (
    DeepResearchResult,
    IntelFinding,
    KnowledgeGraph,
    PESTAnalysis,
)

# Get a logger instance

logger = logging.getLogger(__name__)


# --- Intelligence Gathering Functions ---


async def gather_socmint(topic: str) -> List[Dict[str, str]]:
    """Gathers Social Media Intelligence (SOCMINT)."""
    queries = [
        f'site:linkedin.com intext:"{topic}"',
        f'site:twitter.com intext:"{topic}"',
    ]
    results = search(queries=queries)
    return [
        {
            "source": "SOCMINT",
            "data": f"Profile found at: {url}",
        }
        for url in results
    ]


async def gather_codeint(topic: str) -> List[Dict[str, str]]:
    """Gathers Code Intelligence (CODEINT)."""
    queries = [f'site:github.com "{topic}"', f'site:gitlab.com "{topic}"']
    results = search(queries=queries)
    return [
        {
            "source": "CODEINT",
            "data": f"Code repository mention at: {url}",
        }
        for url in results
    ]


async def gather_finint(topic: str) -> List[Dict[str, str]]:
    """Gathers Financial Intelligence (FININT)."""
    queries = [
        f'"{topic}" AND (sec filings OR "financial statement" OR funding OR investment)'
    ]
    results = search(queries=queries)
    return [
        {"source": "FININT", "data": f"Financial context found at: {url}"}
        for url in results
    ]


async def gather_geoint(topic: str) -> List[Dict[str, str]]:
    """Gathers Geospatial Intelligence (GEOINT)."""
    queries = [f'"{topic}" AND (location OR address OR headquarters)']
    results = search(queries=queries)
    return [
        {"source": "GEOINT", "data": f"Geospatial information found at: {url}"}
        for url in results
    ]


async def gather_techint(topic: str) -> List[Dict[str, str]]:
    """Gathers Technical Intelligence (TECHINT)."""
    queries = [
        f'"{topic}" AND (patent OR "technical paper" OR "research and development" OR technology)'
    ]
    results = search(queries=queries)
    return [
        {"source": "TECHINT", "data": f"Technical insight found at: {url}"}
        for url in results
    ]


async def gather_legalint(topic: str) -> List[Dict[str, str]]:
    """Gathers Legal Intelligence (LEGALINT)."""
    queries = [f'"{topic}" AND (lawsuit OR litigation OR "regulatory action" OR legal)']
    results = search(queries=queries)
    return [
        {"source": "LEGALINT", "data": f"Legal context found at: {url}"}
        for url in results
    ]


async def gather_vulnint(topic: str) -> List[Dict[str, str]]:
    """Gathers Vulnerability Intelligence (VULNINT)."""
    queries = [
        f'site:cve.mitre.org "{topic}"',
        f'site:nvd.nist.gov "{topic}"',
        f'"{topic}" AND (vulnerability OR exploit OR breach)',
    ]
    results = search(queries=queries)
    return [
        {"source": "VULNINT", "data": f"Vulnerability data found at: {url}"}
        for url in results
    ]


# --- AI-Powered Strategic Analysis ---


def _generate_ultimate_report(
    topic: str, intel_data: List[Dict[str, str]], api_key: str
) -> Dict[str, Any]:
    """Generates the final, all-source, strategic intelligence report."""
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-pro")

    prompt = f"""
    As a master intelligence analyst, synthesize the following multi-source OSINT into a
    definitive strategic report on "{topic}". The output must be a single, valid JSON object.

    Produce the following analytical products:
    1.  "target_profile": A detailed profile of the target.
    2.  "strategic_summary": A high-level narrative explaining the target's strategic
        position, key risks, and primary opportunities.
    3.  "pest_analysis": A PEST (Political, Economic, Social, Technological) analysis.
    4.  "intelligence_gaps": A list of critical unanswered questions.
    5.  "recommended_actions": A prioritized list of strategic recommendations.
    6.  "intelligence_findings": A structured list of the most critical findings.
    7.  "knowledge_graph": A graph of all identified entities and their relationships.

    OSINT RAW DATA:
    {json.dumps(intel_data, indent=2)}
    """
    try:
        response = model.generate_content(prompt)
        clean_response = response.text.strip().replace("```json", "").replace("```", "")
        return json.loads(clean_response)
    except Exception as e:
        logger.error(f"Ultimate report generation failed: {e}")
        return {"error": f"AI synthesis failed: {e}"}


# --- Main Orchestration Logic ---


async def conduct_deep_research(topic: str) -> Optional[DeepResearchResult]:
    """Orchestrates the ultimate deep research and intelligence fusion process."""
    logger.info(f"Initiating ultimate intelligence deep dive for: '{topic}'")
    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print("[bold red]Error: GOOGLE_API_KEY is not configured.[/bold red]")
        return None
    tasks = [
        gather_socmint(topic),
        gather_codeint(topic),
        gather_finint(topic),
        gather_geoint(topic),
        gather_techint(topic),
        gather_legalint(topic),
        gather_vulnint(topic),
    ]
    results = await asyncio.gather(*tasks)
    all_intel = [item for sublist in results for item in sublist]

    if not all_intel:
        console.print(
            "[bold yellow]Warning: No significant intelligence findings.[/bold yellow]"
        )
    report_data = _generate_ultimate_report(topic, all_intel, api_key)
    if "error" in report_data:
        console.print(f"[bold red]{report_data['error']}[/bold red]")
        return None
    return DeepResearchResult(
        topic=topic,
        target_profile=report_data.get("target_profile", {}),
        strategic_summary=report_data.get("strategic_summary", "N/A"),
        pest_analysis=PESTAnalysis(**report_data.get("pest_analysis", {})),
        intelligence_gaps=report_data.get("intelligence_gaps", []),
        recommended_actions=report_data.get("recommended_actions", []),
        intelligence_findings=[
            IntelFinding(**f) for f in report_data.get("intelligence_findings", [])
        ],
        knowledge_graph=KnowledgeGraph(
            **report_data.get("knowledge_graph", {"nodes": [], "edges": []})
        ),
    )


# --- NEW: Command-Line Interface Logic ---


deep_research_app = typer.Typer(
    help="Fuses all-source OSINT into a strategic AI-powered intelligence report."
)


@deep_research_app.command("run")
def run_deep_research_cli(
    topic: str = typer.Argument(
        ..., help="The target for ultimate intelligence gathering."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save the full JSON report to a file."
    ),
):
    """
    Executes a full-spectrum intelligence deep dive on the specified topic.
    """
    console.print(
        Panel(
            f"[bold blue]Executing Ultimate Deep Dive On:[/bold blue] [green]{topic}[/green]",
            title="[bold yellow]Chimera Intel[/bold yellow]",
            subtitle="[cyan]All-Source Intelligence Fusion[/cyan]",
        )
    )

    with console.status(
        "[bold green]Synthesizing strategic intelligence...[/bold green]",
        spinner="moon",
    ):
        result = asyncio.run(conduct_deep_research(topic))
    if result:
        console.print(
            f"[bold green]✔ Strategic report complete for '{topic}'.[/bold green]"
        )
        if output_file:
            save_or_print_results(result.model_dump(), output_file)
            console.print(
                f"Full report saved to [bold magenta]{output_file}[/bold magenta]"
            )
        else:
            # Display a rich, structured report in the console

            console.print("\n[bold]Target Profile:[/bold]")
            pprint(result.target_profile)

            console.print(
                Panel(result.strategic_summary, title="[bold]Strategic Summary[/bold]")
            )

            # Display PEST analysis

            pest_panels = [
                Panel(
                    "\n".join(f"- {item}" for item in result.pest_analysis.political),
                    title="[bold]Political[/bold]",
                ),
                Panel(
                    "\n".join(f"- {item}" for item in result.pest_analysis.economic),
                    title="[bold]Economic[/bold]",
                ),
                Panel(
                    "\n".join(f"- {item}" for item in result.pest_analysis.social),
                    title="[bold]Social[/bold]",
                ),
                Panel(
                    "\n".join(
                        f"- {item}" for item in result.pest_analysis.technological
                    ),
                    title="[bold]Technological[/bold]",
                ),
            ]
            console.print(Columns(pest_panels, title="[bold]PEST Analysis[/bold]"))

            table = Table(
                title="Key Intelligence Findings",
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("Source", style="cyan")
            table.add_column("Summary")
            table.add_column("Risk", style="yellow")
            table.add_column("Confidence", style="green")

            for finding in result.intelligence_findings:
                table.add_row(
                    finding.source_type,
                    finding.summary,
                    finding.risk_level,
                    finding.confidence,
                )
            console.print(table)

            console.print("\n[bold]Recommended Actions:[/bold]")
            for action in result.recommended_actions:
                console.print(f"  - [green]{action}[/green]")
    else:
        console.print(
            "[bold red]Strategic analysis failed. Check logs for details.[/bold red]"
        )
        # FIX: Ensure the CLI exits with an error code on failure
        raise typer.Exit(code=1)
