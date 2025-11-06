"""
Threat Actor Emulation Lab.

Provisions and manages isolated Docker containers to safely
run red-team campaigns and TTP emulations.

Requires: pip install docker
"""

import typer
import logging
import json
import docker
import os
from docker.errors import ImageNotFound, APIError, NotFound
from typing import Optional, Dict, Any, List
from .utils import console, save_or_print_results
from .schemas import LabEnvironment

logger = logging.getLogger(__name__)



def _get_docker_image(os_profile: str) -> str:
    """Maps a simple OS profile to a real Docker image."""
    os_profile = os_profile.lower()
    if "ubuntu" in os_profile:
        return f"ubuntu:{os_profile.split(':')[-1]}"
    if "windows" in os_profile:
        # Note: Windows containers are large and have specific host requirements
        logger.warning("Windows containers require a Windows host or specific setup.")
        return "mcr.microsoft.com/windows/servercore:ltsc2022"
    # Default to a simple, common Linux image
    return "ubuntu:latest"


def _provision_docker_lab(
    image_name: str,
    lab_name: str,
    services: List[str]
) -> docker.models.containers.Container:
    """
    Creates and starts a new Docker container for the lab.
    """
    try:
        client = docker.from_env()
    except Exception as e:
        logger.error(f"Failed to connect to Docker daemon: {e}")
        console.print("[bold red]Error:[/bold red] Could not connect to Docker. Is it running?")
        raise typer.Exit(code=1)

    with console.status(f"[bold cyan]Pulling image '{image_name}'...[/bold cyan]"):
        try:
            client.images.pull(image_name)
        except ImageNotFound:
            logger.error(f"Docker image not found: {image_name}")
            console.print(f"[bold red]Error:[/bold red] Docker image '{image_name}' not found.")
            raise typer.Exit(code=1)
        except APIError as e:
            logger.error(f"Docker API error: {e}")
            console.print(f"[bold red]Error:[/bold red] Docker API error: {e}")
            raise typer.Exit(code=1)

    console.print(f"  - Creating container '{lab_name}'...")
    container = client.containers.run(
        image_name,
        name=lab_name,
        detach=True,
        tty=True,  # Keeps the container alive (for most base images)
        remove=False # We want to manage it manually
    )

    # Install services
    if services:
        container.reload() # Get updated state
        if container.status != "running":
            console.print(f"[yellow]Warning:[/yellow] Container '{lab_name}' is not running, skipping service install.")
            return container
            
        with console.status(f"[bold cyan]Installing services in '{lab_name}'...[/bold cyan]"):
            # This is a simple example for Ubuntu-based images
            container.exec_run("apt-get update")
            for service in services:
                console.print(f"  - Installing {service}...")
                exit_code, output = container.exec_run(f"apt-get install -y {service}")
                if exit_code != 0:
                    logger.warning(f"Failed to install {service}: {output.decode()}")
                    console.print(f"[yellow]Warning:[/yellow] Failed to install {service}.")

    return container


def provision_emulation_lab(
    plan_file: str,
    target_profile: Dict[str, Any],
) -> LabEnvironment:
    """
    Provisions a new isolated lab environment based on a target profile
    and an emulation plan.
    """
    try:
        with open(plan_file, "r") as f:
            if plan_file.endswith(".json"):
                plan = json.load(f)
            else:
                import yaml
                plan = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load emulation plan {plan_file}: {e}")
        raise ValueError(f"Could not load plan file: {e}")

    plan_name = plan.get("display_name", plan.get("attack_technique", "Unknown-Plan"))
    lab_name = f"chimera-lab-{plan_name.lower().replace(' ', '-')}-{os.urandom(4).hex()}"
    
    console.print(f"[bold]Provisioning emulation lab: '{lab_name}'...[/bold]")
    
    image_name = _get_docker_image(target_profile.get("os", "linux"))
    
    container = _provision_docker_lab(
        image_name,
        lab_name,
        target_profile.get("services", [])
    )
    
    container.reload()
    ip_address = container.attrs['NetworkSettings']['IPAddress']
    if not ip_address:
        # Fallback for some network modes
        ip_address = container.attrs['NetworkSettings']['Networks'].values()[0]['IPAddress']

    state_file_path = f"lab-state-{container.id[:12]}.json"

    lab = LabEnvironment(
        lab_id=container.id,
        lab_name=lab_name,
        target_profile=target_profile,
        emulation_plan=plan,
        status=container.status,
        ip_address=ip_address,
        state_file_path=state_file_path
    )
    
    logger.info(f"Lab {lab.lab_id} provisioned at {lab.ip_address}")
    
    # Save the state file
    with open(state_file_path, "w") as f:
        f.write(lab.model_dump_json(indent=2))
    console.print(f"[green]Lab state file saved to: {state_file_path}[/green]")

    return lab
    

def destroy_emulation_lab(lab_state_file: str):
    """
    Destroys a provisioned lab environment based on its state file.
    """
    try:
        with open(lab_state_file, "r") as f:
            lab_data = json.load(f)
            lab_id = lab_data.get("lab_id")
            lab_name = lab_data.get("lab_name", lab_id)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Could not read state file {lab_state_file}: {e}")
        raise typer.Exit(code=1)

    console.print(f"[bold]Destroying lab environment '{lab_name}' (ID: {lab_id[:12]})...[/bold]")
    
    try:
        client = docker.from_env()
        container = client.containers.get(lab_id)
        
        console.print("  - Stopping container...")
        container.stop()
        console.print("  - Removing container...")
        container.remove()
        
        # Clean up the state file
        os.remove(lab_state_file)
        
        console.print("[green]Lab environment destroyed.[/green]")
        return {"lab_id": lab_id, "status": "destroyed"}
    except NotFound:
        console.print(f"[yellow]Warning:[/yellow] Container {lab_id[:12]} not found. It may already be destroyed.")
        # Still remove the state file if it exists
        if os.path.exists(lab_state_file):
            os.remove(lab_state_file)
        return {"lab_id": lab_id, "status": "not_found"}
    except Exception as e:
        console.print(f"[bold red]Error during destroy:[/bold red] {e}")
        raise typer.Exit(code=1)
    

# --- Typer CLI Application ---

lab_app = typer.Typer(
    name="lab",
    help="Threat Actor Emulation Lab for running sandboxed campaigns.",
)

@lab_app.command("provision")
def cli_provision_lab(
    plan_file: str = typer.Argument(..., help="Path to the emulation plan (JSON/YAML) from 'red-team' module."),
    target_os: str = typer.Option("linux", help="Target OS for the replica (e.g., 'ubuntu', 'windows')."),
    service: Optional[List[str]] = typer.Option(None, "--service", help="Services to install (e.g., 'apache2', 'mysql-server')."),
):
    """
    Provisions a new isolated lab environment from a plan.
    """
    profile = {"os": target_os, "services": service or []}
    try:
        lab = provision_emulation_lab(plan_file, profile)
        console.print("\n[bold green]Provisioning Complete:[/bold green]")
        save_or_print_results(lab.model_dump(), None)
    except Exception as e:
        console.print(f"[bold red]Error provisioning lab:[/bold red] {e}")
        raise typer.Exit(code=1)

@lab_app.command("destroy")
def cli_destroy_lab(
    lab_state_file: str = typer.Argument(..., help="The state file of the lab to destroy (e.g., 'lab-state-...)."),
):
    """
    Destroys a provisioned lab environment from its state file.
    """
    result = destroy_emulation_lab(lab_state_file)
    save_or_print_results(result, None)