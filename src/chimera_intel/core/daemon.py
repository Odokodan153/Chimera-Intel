"""
Module for running Chimera Intel as a background daemon for continuous monitoring.
"""

import typer
import os
import sys
import time
import subprocess
import logging
from datetime import datetime
from .project_manager import get_active_project
from .utils import console
from .scheduler import is_time_to_run

logger = logging.getLogger(__name__)
PID_FILE = "chimera_daemon.pid"


def _get_daemon_status():
    """Checks if the daemon is currently running by checking the PID file."""
    if not os.path.exists(PID_FILE):
        return None
    try:
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())
        # Check if a process with this PID is actually running

        os.kill(pid, 0)
        return pid
    except (IOError, ValueError, OSError):
        # PID file is stale or process is not running

        os.remove(PID_FILE)
        return None


def _run_workflow(workflow_steps: list, target: str):
    """Executes a series of Chimera Intel commands."""
    for step in workflow_steps:
        try:
            full_command = f"chimera {step.format(target=target)}"
            logger.info(f"Daemon executing workflow step: {full_command}")
            subprocess.run(
                full_command,
                shell=True,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as e:
            logger.error(
                f"Daemon workflow step failed with exit code {e.returncode}: {full_command}"
            )
        except Exception as e:
            logger.error(
                f"An unexpected error occurred during daemon workflow execution: {e}"
            )


def start_daemon():
    """Starts the monitoring daemon as a background process."""
    if _get_daemon_status():
        console.print("[bold yellow]Daemon is already running.[/bold yellow]")
        return
    active_project = get_active_project()
    if (
        not active_project
        or not hasattr(active_project, "daemon_config")
        or not active_project.daemon_config.enabled
    ):
        console.print(
            "[bold red]Error:[/bold red] No active project with an enabled daemon configuration. Use 'chimera project use <name>' and configure the project's YAML file."
        )
        raise typer.Exit(code=1)
    # The magic of creating a daemon: forking the process

    try:
        pid = os.fork()
        if pid > 0:
            # Parent process: exit and let the child run in the background

            console.print(
                f"[bold green]Daemon started successfully with PID {pid}.[/bold green]"
            )
            sys.exit()
    except OSError as e:
        logger.error(f"fork failed: {e}")
        sys.exit(1)
    # Child process: become the session leader

    os.setsid()

    # Write the PID file

    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))
    console.print(
        f"Daemon process started for project '{active_project.project_name}'. Monitoring target '{active_project.domain}'."
    )
    logger.info(
        f"Daemon process started with PID {os.getpid()} for project '{active_project.project_name}'."
    )

    # The main daemon loop - now a scheduler

    target = active_project.domain
    workflows = active_project.daemon_config.workflows

    while True:
        now = datetime.now()

        for workflow in workflows:
            if is_time_to_run(workflow.schedule, now):
                logger.info(f"Workflow '{workflow.name}' is due to run. Executing...")
                _run_workflow(workflow.steps, target)
        # Sleep until the start of the next minute

        time.sleep(60 - now.second)


def stop_daemon():
    """Stops the running daemon process."""
    pid = _get_daemon_status()
    if not pid:
        console.print("[bold yellow]Daemon is not running.[/bold yellow]")
        return
    try:
        os.kill(pid, 15)  # 15 is the SIGTERM signal
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        console.print(
            f"[bold green]Daemon with PID {pid} stopped successfully.[/bold green]"
        )
    except OSError:
        console.print(
            "[bold red]Error:[/bold red] Could not stop the daemon process. It may have already been stopped."
        )
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)


# --- Typer CLI Application ---


daemon_app = typer.Typer()


@daemon_app.command("start")
def start_daemon_command():
    """Starts the Chimera Intel daemon in the background."""
    start_daemon()


@daemon_app.command("stop")
def stop_daemon_command():
    """Stops the Chimera Intel daemon."""
    stop_daemon()


@daemon_app.command("status")
def status_daemon_command():
    """Checks the status of the Chimera Intel daemon."""
    pid = _get_daemon_status()
    if pid:
        active_project = get_active_project()
        project_name = active_project.project_name if active_project else "Unknown"
        console.print(
            f"[bold green]Daemon is running with PID {pid} for project '{project_name}'.[/bold green]"
        )
    else:
        console.print("[bold yellow]Daemon is not running.[/bold yellow]")
