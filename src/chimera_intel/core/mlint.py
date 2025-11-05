# src/chimera_intel/core/mlint.py

import typer
import logging
import json
import asyncio
from typing import Optional

# --- Core MLINT Logic Imports ---

# Database and Graph connectivity
from .database import get_db_session
from .mlint_graph import get_neo4j_driver

# Analysis & Detection Logic
from .mlint_analysis import (
    detect_layering, 
    detect_straw_company,
    AMLAlert
)

# Linking & Correlation Logic
from .mlint_linking import (
    resolve_entity_globally,
    run_trade_correlation_from_db # The "real" DB-backed function
)

# Compliance & Review Queue Logic
from .mlint_compliance import ReviewService

# --- CLI Setup ---

app = typer.Typer(
    help="Global Financial Crime Suite (MLINT 2.0). Links entities, correlates trade, and detects AML risks."
)
logger = logging.getLogger(__name__)


# --- Main Commands ---

@app.command(name="resolve")
def run_resolve(
    entity_id: str = typer.Option(..., "--id", help="Entity ID (e.g., person name, company name, wallet address)"),
    entity_type: str = typer.Option("auto", "--type", help="Type of entity (person, company, wallet, auto)")
):
    """
    Resolve an entity across all financial crime data sources.
    (This is a placeholder for your existing logic)
    """
    typer.echo(f"Resolving entity: {entity_id} (Type: {entity_type})")
    try:
        # result = asyncio.run(resolve_entity_globally(entity_id, entity_type))
        # typer.echo(result.json(indent=2))
        typer.echo("... (Core entity resolution logic would run here) ...")
        typer.secho(f"Placeholder: Entity resolution for {entity_id} complete.", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"Error during resolution: {e}", fg=typer.colors.RED)


@app.command(name="correlate-trade")
def cli_run_trade_correlation(
    trade_id: str = typer.Argument(..., help="Unique ID for the trade/shipping record (e.g., 'bol-123')"),
    payment_id: str = typer.Argument(..., help="Unique ID for the payment transaction (e.g., 'swift-abc')")
):
    """
    Correlate a single trade (Bill of Lading) with a payment from the database.
    """
    typer.echo(f"Attempting to correlate Trade {trade_id} with Payment {payment_id}...")
    try:
        # This calls the "real" function in mlint_linking that uses database sources
        result = asyncio.run(run_trade_correlation_from_db(trade_id, payment_id))
        
        if result.is_match:
            typer.secho(f"--- MATCH FOUND (Confidence: {result.confidence_score:.2%}) ---", fg=typer.colors.GREEN, bold=True)
        else:
            typer.secho(f"--- NO MATCH (Confidence: {result.confidence_score:.2%}) ---", fg=typer.colors.YELLOW, bold=True)
            
        typer.echo(result.json(indent=2))

    except Exception as e:
        typer.secho(f"Error during correlation: {e}", fg=typer.colors.RED)


@app.command(name="detect-layering")
def run_detect_layering(
    start_node_id: str = typer.Argument(..., help="The entity ID (e.g., Wallet or Company ID) to start the path analysis from."),
    node_type: str = typer.Option("Wallet", help="The node label type (e.g., Wallet, Company)."),
    max_depth: int = typer.Option(5, help="Maximum hops to check in the graph."),
    time_window_days: int = typer.Option(7, help="Time window in days for transactions."),
    submit_review: bool = typer.Option(True, help="Automatically submit alerts for analyst review.")
):
    """
    Detect suspicious 'layering' transaction patterns in the graph.
    """
    typer.echo(f"Analyzing graph for layering starting from {node_type} {start_node_id}...")
    driver = None
    try:
        driver = get_neo4j_driver()
        alert = detect_layering(driver, start_node_id, node_type, max_depth, time_window_days)
        
        if alert:
            typer.secho("=== AML Alert: Layering Detected ===", fg=typer.colors.RED, bold=True)
            typer.echo(alert.json(indent=2))
            
            if submit_review:
                try:
                    with get_db_session() as session:
                        service = ReviewService(session)
                        case = service.submit_alert_for_review(alert)
                        typer.secho(f"Alert submitted for review. Case ID: {case.id} (Fusion Count: {case.fusion_count})", fg=typer.colors.CYAN)
                except Exception as e:
                    typer.secho(f"Failed to submit alert for review: {e}", fg=typer.colors.RED)
        else:
            typer.secho(f"No significant layering patterns found starting from {start_node_id}.", fg=typer.colors.GREEN)
    
    except Exception as e:
        logger.error(f"Plugin error during layering detection: {e}", exc_info=True)
        typer.secho(f"An error occurred: {e}", fg=typer.colors.RED)
    finally:
        if driver:
            driver.close()


@app.command(name="check-straw-company")
def run_check_straw_company(
    company_id: str = typer.Argument(..., help="The Company entity ID to analyze."),
    submit_review: bool = typer.Option(True, help="Automatically submit alerts for analyst review.")
):
    """
    Check a company for red flags associated with 'straw' or 'shell' companies.
    """
    typer.echo(f"Analyzing company {company_id} for straw/shell characteristics...")
    driver = None
    try:
        driver = get_neo4j_driver()
        alert = detect_straw_company(driver, company_id)
        
        if alert:
            typer.secho("=== AML Alert: Potential Straw Company ===", fg=typer.colors.RED, bold=True)
            typer.echo(alert.json(indent=2))
            
            if submit_review:
                try:
                    with get_db_session() as session:
                        service = ReviewService(session)
                        case = service.submit_alert_for_review(alert)
                        typer.secho(f"Alert submitted for review. Case ID: {case.id} (Fusion Count: {case.fusion_count})", fg=typer.colors.CYAN)
                except Exception as e:
                    typer.secho(f"Failed to submit alert for review: {e}", fg=typer.colors.RED)
        else:
            typer.secho(f"Company {company_id} does not show obvious signs of a straw company.", fg=typer.colors.GREEN)
    
    except Exception as e:
        logger.error(f"Plugin error during straw company check: {e}", exc_info=True)
        typer.secho(f"An error occurred: {e}", fg=typer.colors.RED)
    finally:
        if driver:
            driver.close()


# --- Case Management Sub-app ---
case_app = typer.Typer(name="cases", help="Manage analyst review cases for AML alerts.")

@case_app.command(name="list")
def list_cases(
    status: str = typer.Option("OPEN", help="Filter by case status (e.g., OPEN, ESCALATED, FALSE_POSITIVE).")
):
    """
    List AML review cases from the database.
    """
    typer.echo(f"Fetching {status.upper()} review cases...")
    try:
        with get_db_session() as session:
            service = ReviewService(session)
            cases = service.get_cases_by_status(status.upper())
            
            if not cases:
                typer.secho(f"No {status.upper()} cases found.", fg=typer.colors.YELLOW)
                return
            
            typer.secho(f"Found {len(cases)} {status.upper()} cases:", bold=True)
            for case in cases:
                typer.echo(f"- ID {case.id} (Count: {case.fusion_count}): {case.alert_type} on entity {case.entity_id} (Assignee: {case.assignee or 'None'})")
                
    except Exception as e:
        typer.secho(f"Error fetching cases: {e}", fg=typer.colors.RED)

@case_app.command(name="view")
def view_case(
    case_id: int = typer.Argument(..., help="The ID of the case to view.")
):
    """
    View the details of a single review case.
    Alert data shown is PII-masked.
    """
    try:
        with get_db_session() as session:
            service = ReviewService(session)
            case = service.get_case_by_id(case_id)
            
            if not case:
                typer.secho(f"Case {case_id} not found.", fg=typer.colors.RED)
                return
            
            typer.secho(f"--- Case {case.id} ---", bold=True)
            typer.echo(f"Entity:   \t{case.entity_id}")
            typer.echo(f"Alert:    \t{case.alert_type}")
            typer.echo(f"Status:   \t{case.status}")
            typer.echo(f"Assignee: \t{case.assignee}")
            typer.echo(f"Fusion Count: \t{case.fusion_count}")
            typer.echo(f"Created:  \t{case.created_at}")
            typer.echo(f"Updated:  \t{case.updated_at}")
            typer.secho("\n--- Notes ---", bold=True)
            typer.echo(case.notes or "[No notes]")
            
            typer.secho("\n--- Masked Alert JSON ---", bold=True)
            # Pretty-print the JSON
            alert_data = json.loads(case.alert_json)
            typer.echo(json.dumps(alert_data, indent=2))
                
    except Exception as e:
        typer.secho(f"Error fetching case {case_id}: {e}", fg=typer.colors.RED)

@case_app.command(name="resolve")
def resolve_case(
    case_id: int = typer.Argument(..., help="The ID of the case to resolve."),
    new_status: str = typer.Argument(..., help="The new status (e.g., ESCALATED, FALSE_POSITIVE)."),
    notes: str = typer.Option(..., "--notes", "-n", help="Analyst notes explaining the resolution."),
    assignee: str = typer.Option("cli_user", "--as", help="User ID of the analyst resolving the case.")
):
    """
    Resolve or update a review case.
    """
    try:
        with get_db_session() as session:
            service = ReviewService(session)
            case = service.resolve_case(case_id, new_status.upper(), notes, assignee)
            
            if not case:
                typer.secho(f"Case {case_id} not found.", fg=typer.colors.RED)
                return
            
            typer.secho(f"Case {case.id} successfully updated.", fg=typer.colors.GREEN)
            typer.echo(f"New Status: {case.status}")
                
    except Exception as e:
        typer.secho(f"Error resolving case {case_id}: {e}", fg=typer.colors.RED)

# Add the 'cases' sub-app to the main 'mlint' app
app.add_typer(case_app)