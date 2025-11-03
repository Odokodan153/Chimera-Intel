"""
AI-Driven Covert Intelligence Agent for Chimera Intel.
This module provides autonomous agents that can plan and execute
multi-step investigations by orchestrating other modules.
"""

import typer
import json
from typing_extensions import Annotated
from typing import List, Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.json import JSON

# --- Real Core Module Imports ---
# This agent now has hard dependencies on these modules.
# It will fail if they are not present.
from .config_loader import API_KEYS
from .ai_core import generate_swot_from_data, AIResult
from .narrative_analyzer import track_narrative
from .personnel_osint import search_personnel
from .corporate_intel import search_company
from .footprint import analyze_footprint
# ---------------------------------

console = Console()

covert_app = typer.Typer(
    name="covert",
    help="Manages AI-driven autonomous investigation agents.",
)


# --- Available Tools for the Agent ---
# The agent's AI planner will select from this list of real functions.
AGENT_TOOLS = {
    "person_intel": search_personnel,
    "company_intel": search_company,
    "digital_footprint": analyze_footprint,
    "narrative_analysis": track_narrative,
}
# ----------------------------------------


@covert_app.command(
    "run", help="Run a multi-step investigation with an autonomous agent."
)
def run_investigation(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="The initial target entity (e.g., person, company).",
            prompt=True,
        ),
    ],
    objective: Annotated[
        str,
        typer.Option(
            "--objective",
            "-o",
            help="The high-level objective of the investigation.",
            prompt="Enter the investigation objective (e.g., 'Find all assets and map influence')",
        ),
    ],
):
    """
    Plans and executes a multi-step investigation, linking person ->
    company -> asset -> digital footprint -> narrative analysis.
    """
    console.print(
        f"Initiating autonomous investigation for target: [bold cyan]'{target}'[/bold cyan]"
    )
    console.print(f"Objective: [bold]'{objective}'[/bold]")

    ai_api_key = API_KEYS.google_api_key
    if not ai_api_key:
        console.print(
            "[bold red]Error:[/bold red] GOOGLE_API_KEY is not set. Cannot generate investigation plan."
        )
        raise typer.Exit(code=1)

    # 1. Generate the Investigation Plan
    console.print("[yellow]Generating investigation plan with AI...[/yellow]")
    tool_list = "\n".join(
        [f"- {name}" for name in AGENT_TOOLS.keys()]
    )
    
    plan_prompt = (
        "You are an autonomous covert intelligence investigation planner. "
        "Your task is to create a step-by-step plan to achieve a high-level objective, starting from an initial target. "
        "You must only use the tools provided. The output must be a valid JSON list of steps. "
        "Each step must be an object with 'module' (the tool to use) and 'query' (the string argument for the tool).\n"
        "Link the steps together: the output of one step can inform the query for the next.\n"
        "For example, if the plan is: person -> company -> narrative, a good plan would be:\n"
        '[{"module": "person_intel", "query": "John Doe"}, {"module": "company_intel", "query": "Acme Corp"}, {"module": "narrative_analysis", "query": "Acme Corp influence"}]\n\n'
        f"**Available Tools:**\n{tool_list}\n\n"
        f"**Target:** {target}\n"
        f"**Objective:** {objective}\n\n"
        "**JSON Investigation Plan:**"
    )

    try:
        ai_result: AIResult = generate_swot_from_data(plan_prompt, ai_api_key)
        if ai_result.error:
            console.print(f"[bold red]AI Error:[/bold red] {ai_result.error}")
            raise typer.Exit(code=1)

        plan_text = ai_result.analysis_text.strip().replace("```json", "").replace("```", "")
        plan: List[Dict[str, str]] = json.loads(plan_text)
        
        console.print(Panel(JSON(plan_text), title="[bold green]Investigation Plan[/bold green]", border_style="green"))

    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error parsing AI plan:[/bold red] {e}")
        console.print(f"[bold red]Raw AI Output:[/bold red]\n{ai_result.analysis_text}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]An error occurred during planning:[/bold red] {e}")
        raise typer.Exit(code=1)

    # 2. Execute the Investigation Plan
    console.print("\n[bold cyan]--- EXECUTING INVESTIGATION PLAN ---[/bold cyan]")
    investigation_results = []
    
    try:
        for i, step in enumerate(plan):
            module_name = step.get("module")
            query = step.get("query")
            
            console.print(f"\n[bold]Step {i+1}:[/bold] Calling module [magenta]'{module_name}'[/magenta] with query: [yellow]'{query}'[/yellow]")
            
            tool_function = AGENT_TOOLS.get(module_name)
            
            if not tool_function:
                console.print(f"  [bold red]Error:[/bold red] Module '{module_name}' not found in tool list.")
                continue
            
            # Execute the real function from the imported module
            # We assume all functions take a single string argument and return a list/dict
            result = tool_function(query)
            investigation_results.append(
                {"step": i + 1, "module": module_name, "query": query, "result": result}
            )
            
            # Don't print huge data blobs, just a summary
            if isinstance(result, list) and len(result) > 0:
                 console.print(f"  [green]Success:[/green] Received {len(result)} items.")
            elif isinstance(result, dict):
                 console.print(f"  [green]Success:[/green] Received result with keys: {list(result.keys())}")
            else:
                 console.print(f"  [green]Success:[/green] {result}")

        console.print("\n[bold green]--- INVESTIGATION COMPLETE ---[/bold green]")
        
        # 3. Final Summary (Could also be an AI call)
        console.print(Panel(
            f"Target: {target}\nObjective: {objective}\nSteps Executed: {len(plan)}\nSummary: The agent successfully executed the plan, gathering data from {len(plan)} modules.",
            title="[bold blue]Final Report Summary[/bold blue]",
            border_style="blue"
        ))
        
        # Optionally, save full results
        with open(f"investigation_report_{target.replace(' ', '_')}.json", "w") as f:
            json.dump(investigation_results, f, indent=2, default=str)
        console.print(f"Full investigation results saved to 'investigation_report_{target.replace(' ', '_')}.json'")

    except Exception as e:
        console.print(f"[bold red]An error occurred during execution:[/bold red] {e}")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    covert_app()