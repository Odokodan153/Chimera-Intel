import psycopg2
from typing import Dict, Any, Optional, List
import matplotlib.pyplot as plt
import pandas as pd
import typer
import networkx as nx 
from .utils import console, save_or_print_results  
from .database import save_scan_to_db
from rich.markdown import Markdown  
from .schemas import InfluenceMapResult, QuickWinMetricsResult 
from .config_loader import API_KEYS  
import logging

logger = logging.getLogger(__name__)

analytics_app = typer.Typer()


def get_negotiation_kpis(db_params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates and returns a dictionary of Key Performance Indicators (KPIs)
    for negotiation performance.
    """
    conn = None
    if not all(db_params.values()):
        return {"error": "Database connection parameters are missing."}

    kpis = {}  # <-- FIX: Initialize kpis dictionary before the try block
    try:
        conn = psycopg2.connect(**db_params)
        if not conn:
            return {"error": "Could not connect to the database."}
        # kpis = {} <-- MOVED
        with conn.cursor() as cursor:
            # --- Success Rate ---

            cursor.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE analysis->>'intent' = 'acceptance') * 100.0 / COUNT(*)
                FROM messages
                WHERE analysis->>'intent' IN ('acceptance', 'rejection');
            """
            )
            success_rate = cursor.fetchone()[0]
            kpis["success_rate"] = round(success_rate, 2) if success_rate else 0

            # --- Average Deal Value ---

            cursor.execute(
                """
                SELECT AVG((analysis->>'offer_amount')::float)
                FROM messages
                WHERE analysis->>'intent' = 'acceptance';
            """
            )
            avg_deal_value = cursor.fetchone()[0]
            kpis["average_deal_value"] = (
                round(avg_deal_value, 2) if avg_deal_value else 0
            )

            # --- Average Negotiation Length ---

            cursor.execute(
                """
                SELECT AVG(turn_count) FROM (
                    SELECT negotiation_id, COUNT(*) as turn_count
                    FROM messages
                    GROUP BY negotiation_id
                ) as negotiation_lengths;
            """
            )
            avg_length = cursor.fetchone()[0]
            kpis["average_negotiation_length"] = (
                round(avg_length, 2) if avg_length else 0
            )
    except Exception as e:
        kpis["error"] = f"An error occurred while calculating KPIs: {e}"
    finally:
        if conn:
            conn.close()
    return kpis


# +++ NEW FUNCTION (REAL IMPLEMENTATION) +++
def get_influence_mapping(
    db_params: Dict[str, Any],
    target_space: str,
    geography: Optional[str] = None,
) -> InfluenceMapResult:
    """
    Maps and scores the influence of key entities by building a graph
    from database records (e.g., 'mentions' or 'social_connections').
    
    NOTE: This assumes a table named 'social_connections' exists in the
    database, populated by other tools (like social_osint).
    """
    conn = None
    if not all(db_params.values()):
        return InfluenceMapResult(
            target_space=target_space,
            geography=geography,
            influence_scores={},
            analysis_text="",
            error="Database connection parameters are missing.",
        )

    try:
        conn = psycopg2.connect(**db_params)
        if not conn:
            return InfluenceMapResult(
                target_space=target_space,
                geography=geography,
                influence_scores={},
                analysis_text="",
                error="Could not connect to the database.",
            )

        # This query assumes a 'social_connections' table.
        # It could be 'mentions', 'retweets', etc.
        # It also assumes 'target_space' and 'geography' are filterable columns.
        
        # We will query for 'source' -> 'target' connections (e.g., A retweets B)
        # This builds a directed graph where edges point to the person being *followed* or *mentioned*.
        
        query_params: List[Any] = [target_space]
        sql_query = """
            SELECT source_user, target_user, weight
            FROM social_connections
            WHERE target_space = %s
        """
        if geography:
            sql_query += " AND geography = %s"
            query_params.append(geography)
            
        with console.status("[bold cyan]Querying graph connections from DB...[/bold cyan]"):
            df = pd.read_sql_query(sql_query, conn, params=query_params)

        if df.empty:
            return InfluenceMapResult(
                target_space=target_space,
                geography=geography,
                influence_scores={},
                analysis_text="",
                error=f"No social connections found for target space '{target_space}'.",
            )
        
        with console.status("[bold cyan]Building influence graph...[/bold cyan]"):
            # Create a directed graph
            G = nx.from_pandas_edgelist(
                df,
                source="source_user",
                target="target_user",
                edge_attr="weight",
                create_using=nx.DiGraph(),
            )

        console.print(f"Graph built with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.")
        
        # Calculate influence scores using PageRank
        # PageRank is ideal for this: a link from A to B is a "vote" for B's importance.
        with console.status("[bold cyan]Calculating PageRank influence scores...[/bold cyan]"):
            pagerank_scores = nx.pagerank(G, weight="weight")
        
        # Sort by influence
        sorted_scores = sorted(pagerank_scores.items(), key=lambda item: item[1], reverse=True)
        
        top_influencers = dict(sorted_scores[:20])
        
        # Generate analysis text
        analysis_text = f"### Influence Map: '{target_space.title()}'\n\n"
        analysis_text += f"**Geography:** {geography or 'Global'}\n\n"
        analysis_text += "**Top 5 Influencers (by PageRank):**\n"
        
        for i, (user, score) in enumerate(sorted_scores[:5]):
            analysis_text += f"  {i+1}. **{user}** (Score: {score:.4f})\n"
            
        analysis_text += "\n**Analysis:**\n"
        analysis_text += (
            f"A network graph of {G.number_of_nodes()} entities and "
            f"{G.number_of_edges()} connections was analyzed. "
            "Influence is calculated using PageRank, where entities 'voted' for "
            "by other high-influence entities are scored higher. "
            f"The primary levers for influence in this space are **{sorted_scores[0][0]}** "
            f"and **{sorted_scores[1][0]}**.\n"
        )
        
        return InfluenceMapResult(
            target_space=target_space,
            geography=geography,
            influence_scores=top_influencers,
            analysis_text=analysis_text,
            error=None,
        )

    except Exception as e:
        return InfluenceMapResult(
            target_space=target_space,
            geography=geography,
            influence_scores={},
            analysis_text="",
            error=f"An error occurred during graph analysis: {e}",
        )
    finally:
        if conn:
            conn.close()


# --- NEW METRICS FUNCTIONS ---

def _get_ttfd_subdomain(cursor, project_name: str) -> Optional[float]:
    """Metric 1: Time to first discovery for new subdomains."""
    try:
        # 1. Get project start time
        cursor.execute("SELECT created_at FROM projects WHERE name = %s", (project_name,))
        start_time_record = cursor.fetchone()
        if not start_time_record:
            return None
        start_time = start_time_record[0]

        # 2. Get all footprint scans, ordered
        cursor.execute(
            """
            SELECT result, timestamp FROM scan_results 
            WHERE project_name = %s AND module = 'footprint' 
            ORDER BY timestamp ASC
            """,
            (project_name,)
        )
        all_scans = cursor.fetchall()

        if len(all_scans) < 2:
            return None  # Need at least two scans to find a "new" one

        # 3. Find the first scan with a new subdomain
        baseline_subdomains = set(p['domain'] for p in all_scans[0][0]['footprint']['subdomains']['results'])
        
        for scan_result, scan_time in all_scans[1:]:
            try:
                current_subdomains = set(p['domain'] for p in scan_result['footprint']['subdomains']['results'])
                new_subdomains = current_subdomains - baseline_subdomains
                if new_subdomains:
                    # Found the first scan with new subdomains
                    time_diff = (scan_time - start_time).total_seconds() / 3600.0
                    return round(time_diff, 2)
            except KeyError:
                continue # Skip malformed scan results
        
        return None  # No new subdomains found
    except Exception as e:
        logger.error(f"Error calculating TTFD: {e}")
        return None

def _get_corroboration_rate(cursor, project_name: str) -> Optional[float]:
    """Metric 2: % of findings with >= 2 corroborating sources."""
    try:
        cursor.execute("SELECT result FROM scan_results WHERE project_name = %s", (project_name,))
        all_results = cursor.fetchall()
        
        total_findings = 0
        corroborated_findings = 0
        
        for (result_json,) in all_results:
            # Recursively find all lists of 'ScoredResult' (which have a 'sources' key)
            def find_scored_results(data):
                nonlocal total_findings, corroborated_findings
                if isinstance(data, dict):
                    if 'sources' in data and 'confidence' in data: # Looks like a ScoredResult
                        total_findings += 1
                        if len(data.get('sources', [])) >= 2:
                            corroborated_findings += 1
                    else:
                        for v in data.values():
                            find_scored_results(v)
                elif isinstance(data, list):
                    for item in data:
                        find_scored_results(item)

            find_scored_results(result_json)

        if total_findings == 0:
            return 0.0
        
        return round((corroborated_findings / total_findings) * 100.0, 2)
    except Exception as e:
        logger.error(f"Error calculating corroboration rate: {e}")
        return None

def _get_fp_rate_playbook(cursor, project_name: str) -> Dict[str, float]:
    """Metric 3: False positive rate per playbook."""
    try:
        # This assumes the 'entity_id' in 'reviewcase' stores the 'project_name'
        cursor.execute(
            """
            SELECT 
                alert_type, 
                COUNT(*) FILTER (WHERE status = 'FALSE_POSITIVE') AS fp_count, 
                COUNT(*) AS total_count 
            FROM reviewcase 
            WHERE entity_id = %s 
            GROUP BY alert_type
            """,
            (project_name,)
        )
        fp_rates = {}
        records = cursor.fetchall()
        for alert_type, fp_count, total_count in records:
            if total_count > 0 and fp_count is not None:
                fp_rates[alert_type] = round((fp_count / total_count) * 100.0, 2)
            else:
                fp_rates[alert_type] = 0.0
        return fp_rates
    except Exception as e:
        logger.error(f"Error calculating FP rate: {e}")
        return {}

def _get_mttc_alert(cursor, project_name: str) -> Optional[float]:
    """Metric 4: Mean time to close (MTTC) for alerts (as proxy for MTTI)."""
    try:
        # This assumes the 'entity_id' in 'reviewcase' stores the 'project_name'
        cursor.execute(
            """
            SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at))) 
            FROM reviewcase 
            WHERE entity_id = %s AND status != 'OPEN'
            """,
            (project_name,)
        )
        avg_seconds = cursor.fetchone()[0]
        
        if avg_seconds is None:
            return 0.0
        
        return round(avg_seconds / 3600.0, 2) # Return in hours
    except Exception as e:
        logger.error(f"Error calculating MTTC: {e}")
        return None

def _get_asset_coverage(cursor, project_name: str) -> Optional[int]:
    """Metric 5: Total unique discovered subdomains."""
    try:
        cursor.execute(
            """
            SELECT result FROM scan_results 
            WHERE project_name = %s AND module = 'footprint' 
            ORDER BY timestamp DESC LIMIT 1
            """,
            (project_name,)
        )
        latest_scan = cursor.fetchone()
        if not latest_scan:
            return 0
            
        # Extract total_unique from the schema
        total_unique = latest_scan[0].get('footprint', {}).get('subdomains', {}).get('total_unique', 0)
        return total_unique
    except Exception as e:
        logger.error(f"Error calculating asset coverage: {e}")
        return None


def get_quick_win_metrics(db_params: Dict[str, Any], project_name: str) -> QuickWinMetricsResult:
    """
    Calculates a set of 'quick win' metrics for a specific project.
    """
    conn = None
    if not all(db_params.values()):
        return QuickWinMetricsResult(error="Database connection parameters are missing.")
    
    try:
        conn = psycopg2.connect(**db_params)
        with conn.cursor() as cursor:
            
            # Check if project exists
            cursor.execute("SELECT id FROM projects WHERE name = %s", (project_name,))
            if not cursor.fetchone():
                return QuickWinMetricsResult(error=f"Project '{project_name}' not found.")

            # Calculate metrics
            ttfd = _get_ttfd_subdomain(cursor, project_name)
            corroboration = _get_corroboration_rate(cursor, project_name)
            fp_rates = _get_fp_rate_playbook(cursor, project_name)
            mttc = _get_mttc_alert(cursor, project_name)
            coverage = _get_asset_coverage(cursor, project_name)

            return QuickWinMetricsResult(
                project_name=project_name,
                time_to_first_subdomain_discovery_hours=ttfd,
                corroboration_rate_percent=corroboration,
                false_positive_rate_by_playbook=fp_rates,
                mean_time_to_close_alert_hours=mttc,
                total_unique_subdomains_found=coverage
            )

    except Exception as e:
        logger.error(f"Failed to get quick win metrics: {e}", exc_info=True)
        return QuickWinMetricsResult(error=f"An error occurred: {e}")
    finally:
        if conn:
            conn.close()

# --- END NEW METRICS ---


@analytics_app.command("plot-sentiment")
def plot_sentiment_trajectory(
    negotiation_id: str = typer.Argument(
        ..., help="The ID of the negotiation to plot."
    ),
    output_path: Optional[str] = typer.Option(
        None, "--output", "-o", help="Path to save the plot image."
    ),
):
    """
    Retrieves the sentiment scores for a given negotiation and plots them over time.
    """
    db_params = {
        "dbname": getattr(API_KEYS, "db_name", None),
        "user": getattr(API_KEYS, "db_user", None),
        "password": getattr(API_KEYS, "db_password", None),
        "host": getattr(API_KEYS, "db_host", None),
    }
    conn = None
    if not all(db_params.values()):
        typer.echo("Error: Database connection parameters are missing.")
        return
    try:
        conn = psycopg2.connect(**db_params)
        if not conn:
            typer.echo("Error: Could not connect to the database.")
            return
        query = """
            SELECT
                timestamp,
                (analysis->>'tone_score')::float as sentiment
            FROM messages
            WHERE negotiation_id = %s
            ORDER BY timestamp;
        """
        df = pd.read_sql_query(query, conn, params=[negotiation_id])  # type: ignore

        if df.empty:
            typer.echo(f"No messages found for negotiation ID: {negotiation_id}")
            return
        plt.figure(figsize=(12, 6))
        plt.plot(df["timestamp"], df["sentiment"], marker="o", linestyle="-")

        plt.title(f"Sentiment Trajectory for Negotiation: {negotiation_id}")
        plt.xlabel("Time")
        plt.ylabel("Sentiment Score (-1 to 1)")
        plt.grid(True)
        plt.ylim(-1.1, 1.1)

        plt.gcf().autofmt_xdate()

        if output_path:
            plt.savefig(output_path)
            typer.echo(f"Plot saved to {output_path}")
        else:
            plt.show()
    except Exception as e:
        typer.echo(f"An error occurred while plotting sentiment trajectory: {e}")
    finally:
        if conn:
            conn.close()


# +++ NEW COMMAND (USING REAL FUNCTION) +++
@analytics_app.command("influence-mapping")
def run_influence_mapping(
    target_space: str = typer.Argument(
        ..., help="The target space (e.g., 'ai_safety') to query in the DB."
    ),
    geography: Optional[str] = typer.Option(
        None, "--geography", "-g", help="The specific country or region (e.g., 'USA')."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Maps and scores influence of key entities from the database.
    """
    db_params = {
        "dbname": getattr(API_KEYS, "db_name", None),
        "user": getattr(API_KEYS, "db_user", None),
        "password": getattr(API_KEYS, "db_password", None),
        "host": getattr(API_KEYS, "db_host", None),
    }
    
    results_model = get_influence_mapping(db_params, target_space, geography)

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)

    console.print(
        f"\n--- [bold]Influence Map: {target_space.title()}[/bold] ---\n"
    )
    console.print(Markdown(results_model.analysis_text))

    if output_file:
        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        target_name = (
            f"{target_space}_{geography}_influence"
            if geography
            else f"{target_space}_influence"
        )
        save_scan_to_db(
            target=target_name, module="analytics_influence_map", data=results_dict
        )


# +++ NEW COMMAND FOR QUICK METRICS +++
@analytics_app.command("quick-metrics")
def run_quick_win_metrics(
    project_name: str = typer.Argument(
        ..., help="The name of the project to calculate metrics for."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Calculates key 'quick win' performance metrics for a project.
    """
    db_params = {
        "dbname": getattr(API_KEYS, "db_name", None),
        "user": getattr(API_KEYS, "db_user", None),
        "password": getattr(API_KEYS, "db_password", None),
        "host": getattr(API_KEYS, "db_host", None),
    }

    with console.status(f"[bold cyan]Calculating quick-win metrics for '{project_name}'...[/bold cyan]"):
        results_model = get_quick_win_metrics(db_params, project_name)

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)

    console.print(
        f"\n--- [bold]Quick-Win Metrics: {project_name}[/bold] ---\n"
    )
    
    results_dict = results_model.model_dump(exclude_none=True, exclude={"project_name"})
    
    # Pretty print the metrics
    console.print(f"  [bold]Time to First New Subdomain:[/bold] {results_model.time_to_first_subdomain_discovery_hours} hours")
    console.print(f"  [bold]Finding Corroboration Rate:[/bold] {results_model.corroboration_rate_percent}%")
    console.print(f"  [bold]Mean Time to Close Alert:[/bold] {results_model.mean_time_to_close_alert_hours} hours")
    console.print(f"  [bold]Total Unique Subdomains Found:[/bold] {results_model.total_unique_subdomains_found}")
    
    console.print("\n  [bold]False Positive Rate by Playbook:[/bold]")
    if results_model.false_positive_rate_by_playbook:
        for playbook, rate in results_model.false_positive_rate_by_playbook.items():
            console.print(f"    - {playbook}: {rate}%")
    else:
        console.print("    - No playbook data found.")

    if output_file:
        save_or_print_results(results_dict, output_file)


if __name__ == "__main__":
    analytics_app()