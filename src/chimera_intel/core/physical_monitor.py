"""
Module for Physical World Competitor Monitoring (GEOINT + IMINT).

This module orchestrates IMINT tools to monitor key physical locations
(e.g., factories, HQs) defined in a project. It compares satellite/drone
imagery provided by an analyst to detect physical changes and shifts in
activity (e.g., construction, changes in vehicle/container volume).
"""

import typer
import logging
import json
import shutil
from pathlib import Path
from typing import Dict, Any
from .schemas import (
    ProjectConfig,
    KeyLocation
)
from .utils import console
from .database import save_scan_to_db, get_db_connection
from .project_manager import list_projects, get_project_config_by_name
from .alert_manager import alert_manager_instance, AlertLevel
from .scheduler import add_job
from .imint import compare_image_changes, perform_object_detection

logger = logging.getLogger(__name__)

# Define the root directory where analysts drop imagery
PHYSICAL_MONITOR_DIR = Path("physical_monitoring_assets")
# Define objects of interest for logistics/activity monitoring
OBJECTS_OF_INTEREST = {"truck", "car", "boat", "airplane", "bus", "train"}

def _get_last_analysis(project_name: str, location_name: str) -> Dict[str, Any]:
    """
    Retrieves the last analysis (e.g., object counts) for a location
    from the scan_results database.
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # The "target" for this module is "project_name/location_name"
            target_str = f"{project_name}/{location_name}"
            cursor.execute(
                """
                SELECT result FROM scan_results
                WHERE target = %s AND module = %s
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (target_str, "physical_monitor")
            )
            record = cursor.fetchone()
            if record:
                return json.loads(record[0])
                
    except Exception as e:
        logger.error(f"Failed to get last scan results from DB for '{target_str}': {e}")
    finally:
        if conn:
            conn.close()
    return {}


def analyze_location_imagery(project: ProjectConfig, location: KeyLocation):
    """
    Analyzes a single location for a project.
    
    It looks for 'image_before.png' and 'image_after.png' in the
    'physical_monitoring_assets/<project_name>/<location_name>/' directory.
    """
    project_name = project.project_name
    location_name = location.name
    location_dir = PHYSICAL_MONITOR_DIR / project_name / location_name
    
    if not location_dir.exists():
        location_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created directory for location: {location_dir}")
    
    img_before_path = location_dir / "image_before.png"
    img_after_path = location_dir / "image_after.png"
    diff_output_path = location_dir / "last_run_diff.png"

    if not img_before_path.exists() or not img_after_path.exists():
        logger.info(
            f"Skipping location '{location_name}'. Analyst must provide "
            f"'image_before.png' and 'image_after.png' in {location_dir}"
        )
        return

    logger.info(f"Analyzing changes for location: {location_name}")
    
    try:
        # 1. Get object counts from the *last* run
        last_analysis = _get_last_analysis(project_name, location_name)
        last_object_counts = last_analysis.get("object_counts", {})

        # 2. Run visual change detection
        diff_results = compare_image_changes(
            str(img_before_path), str(img_after_path), str(diff_output_path)
        )
        if diff_results.get("status", "").startswith("Significant change"):
            logger.warning(
                f"Significant visual change detected for '{location_name}'!"
            )
            alert_manager_instance.dispatch_alert(
                title=f"Physical Change Detected: {location.name}",
                message=(
                    f"Significant visual change (construction?) detected at '{location.name}' ({location.address}).\n"
                    f"Difference score: {diff_results.get('difference_score')}\n"
                    f"Diff image saved to: {diff_output_path}"
                ),
                level=AlertLevel.WARNING,
                provenance={"module": "physical_monitor", "project": project_name, "location": location_name}
            )

        # 3. Run new object detection on the 'after' image
        new_object_counts = perform_object_detection(str(img_after_path))
        
        # 4. Compare object counts and alert
        for obj, new_count in new_object_counts.items():
            if obj not in OBJECTS_OF_INTEREST:
                continue # Skip uninteresting objects
                
            old_count = last_object_counts.get(obj, 0)
            if new_count != old_count:
                change_percent = (
                    (new_count - old_count) / old_count * 100
                ) if old_count > 0 else 100.0
                
                if abs(change_percent) > 25.0: # Alert on > 25% change
                    direction = "increase" if new_count > old_count else "decrease"
                    logger.warning(
                        f"Logistics alert for '{location_name}': {obj} count changed from {old_count} to {new_count}."
                    )
                    alert_manager_instance.dispatch_alert(
                        title=f"Logistics Activity Alert: {location.name}",
                        message=(
                            f"Significant {direction} in '{obj}' count at '{location.name}'.\n"
                            f"Previous count: {old_count}\n"
                            f"Current count: {new_count} ({change_percent:+.1f}%)"
                        ),
                        level=AlertLevel.WARNING,
                        provenance={"module": "physical_monitor", "project": project_name, "location": location_name}
                    )
        
        # 5. Save this run's results to the DB
        scan_data = {
            "object_counts": new_object_counts,
            "last_diff_results": diff_results,
            "image_analyzed": str(img_after_path)
        }
        save_scan_to_db(
            target=f"{project_name}/{location_name}",
            module="physical_monitor",
            data=scan_data
        )
        
        # 6. Cycle images: move 'after' to 'before' for the next run
        shutil.move(str(img_after_path), str(img_before_path))
        logger.info(f"Moved '{img_after_path.name}' to '{img_before_path.name}' for next baseline.")

    except Exception as e:
        logger.error(f"Failed to analyze location '{location_name}': {e}", exc_info=True)


def run_all_physical_monitors():
    """
    Wrapper function for the scheduler.
    Iterates through all projects and runs the physical monitor for each location.
    """
    logger.info("DAEMON: Starting scheduled run for physical location monitor...")
    try:
        project_names = list_projects()
        if not project_names:
            logger.info("DAEMON: No projects found to monitor.")
            return

        logger.info(f"DAEMON: Found {len(project_names)} projects for physical monitoring.")
        for project_name in project_names:
            try:
                config = get_project_config_by_name(project_name)
                if not config or not config.key_locations:
                    continue
                
                for location in config.key_locations:
                    analyze_location_imagery(config, location)
                    
            except Exception as e:
                logger.error(
                    f"DAEMON: Unhandled error while monitoring project '{project_name}': {e}",
                    exc_info=True
                )
        logger.info("DAEMON: Finished scheduled run for physical location monitor.")
    except Exception as e:
        logger.error(
            f"DAEMON: Critical error during job startup (e.g., DB connection): {e}",
            exc_info=True
        )

# --- Typer CLI Application ---

phys_mon_app = typer.Typer(help="Physical (GEOINT/IMINT) location monitoring tools.")

@phys_mon_app.command("monitor-schedule-add")
def schedule_physical_monitor(
    schedule: str = typer.Option(
        "0 */4 * * *", # Every 4 hours
        "--schedule",
        "-s",
        help="Cron schedule (e.g., '0 */4 * * *' for every 4 hours)."
    ),
):
    """Schedules the physical location monitor to run periodically.
    
    This job will iterate through all projects, find their defined
    key_locations, and analyze imagery found in the
    'physical_monitoring_assets/' directory for changes.
    """
    try:
        job_id = "global_physical_location_monitor"
        add_job(
            func=run_all_physical_monitors,
            trigger="cron",
            cron_schedule=schedule,
            job_id=job_id,
            kwargs={},
        )
        typer.echo(
            f"[bold green]Successfully scheduled physical monitor job '{job_id}' "
            f"with schedule: '{schedule}'[/bold green]"
        )
        typer.echo("The daemon will now run this check automatically.")
    except Exception as e:
        typer.echo(f"An unexpected error occurred while scheduling: {e}", err=True)
        raise typer.Exit(code=1)

@phys_mon_app.command("run-once")
def run_once(
    project_name: str = typer.Option(
        ..., 
        "--project",
        "-p",
        help="The specific project name to run the monitor for."
    ),
    location_name: str = typer.Option(
        ...,
        "--location",
        "-l",
        help="The specific location name to analyze (must match config)."
    )
):
    """
    Runs the physical monitor a single time for a specific project and location.
    
    Ensures 'image_before.png' and 'image_after.png' exist in the
    'physical_monitoring_assets/<project>/<location>/' directory first.
    """
    try:
        config = get_project_config_by_name(project_name)
        if not config:
            console.print(f"[bold red]Error:[/bold red] Project '{project_name}' not found.")
            raise typer.Exit(code=1)
            
        location_to_run = None
        for loc in config.key_locations:
            if loc.name.lower() == location_name.lower():
                location_to_run = loc
                break
        
        if not location_to_run:
            console.print(f"[bold red]Error:[/bold red] Location '{location_name}' not found in project '{project_name}'.")
            raise typer.Exit(code=1)

        typer.echo(f"Starting manual physical monitor run for: {project_name}/{location_name}")
        analyze_location_imagery(config, location_to_run)
        typer.echo(f"Manual run complete for: {project_name}/{location_name}")
        
    except Exception as e:
        typer.echo(f"An unexpected error occurred during the run: {e}", err=True)
        raise typer.Exit(code=1)