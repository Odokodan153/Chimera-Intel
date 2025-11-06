"""
Deception & Honeypot Operations Module for Chimera Intel.

(Updated to handle existing containers and flexible port definitions)
"""

import typer
import docker
import docker.errors
from rich.console import Console

console = Console()

deception_app = typer.Typer(
    name="deception",
    help="Active defense through deception and honeypot operations.",
)

# A map of supported honeypot types, now including their internal port
HONEYPOT_IMAGES = {
    "ssh": {"image": "cowrie/cowrie", "internal_port": 2222},
    "telnet": {"image": "cowrie/cowrie", "internal_port": 2223},
    # Add new honeypots here, e.g.:
    # "http": {"image": "some/http-honeypot", "internal_port": 8080},
}


@deception_app.command("deploy-honeypot", help="Deploy a containerized honeypot.")
def deploy_honeypot(
    honeypot_type: str = typer.Option(
        ...,
        "--type",
        "-t",
        help="The type of honeypot to deploy (e.g., 'ssh', 'telnet').",
    ),
    port: int = typer.Option(
        ...,
        "--port",
        "-p",
        help="The external host port to expose the honeypot on.",
    ),
):
    """
    Deploys a low-interaction, containerized honeypot to lure and identify
    adversaries.
    """
    honeypot_type = honeypot_type.lower()
    honeypot_config = HONEYPOT_IMAGES.get(honeypot_type)

    if not honeypot_config:
        console.print(
            f"[bold red]Error:[/bold red] Honeypot type '{honeypot_type}' is not supported. Supported types: {list(HONEYPOT_IMAGES.keys())}"
        )
        raise typer.Exit(code=1)

    image_name = honeypot_config["image"]
    internal_port = honeypot_config["internal_port"]
    container_name = f"chimera-honeypot-{honeypot_type}-{port}"

    console.print(
        f"Deploying '{honeypot_type}' honeypot using image '{image_name}' on port {port}..."
    )

    try:
        client = docker.from_env()
        # Test if Docker daemon is running
        client.ping()

        # 1. Check for and remove existing container
        try:
            existing_container = client.containers.get(container_name)
            console.print(
                f"[yellow]Found existing container '{container_name}'. Stopping and removing it...[/yellow]"
            )
            existing_container.stop()
            existing_container.remove()
        except docker.errors.NotFound:
            pass  # No existing container, good to proceed
        except Exception as e:
            console.print(f"[bold red]Error handling existing container:[/bold red] {e}")
            raise typer.Exit(code=1)

        # 2. Check if image exists locally before pulling
        try:
            client.images.get(image_name)
            console.print(f"Image '{image_name}' already exists locally.")
        except docker.errors.ImageNotFound:
            console.print(f"Pulling image '{image_name}'... (This may take a moment)")
            client.images.pull(image_name)

        # 3. Run the new container
        container = client.containers.run(
            image=image_name,
            detach=True,
            ports={f"{internal_port}/tcp": port},
            name=container_name,
        )

        console.print("\n[bold green]✅ Honeypot deployed successfully![/bold green]")
        console.print(f"   - Container Name: [cyan]{container_name}[/cyan]")
        console.print(f"   - Container ID: [cyan]{container.short_id}[/cyan]")
        console.print(f"   - Exposed Port: Host {port} -> Container {internal_port}")
        console.print("\nTo view attacker interactions, run:")
        console.print(f"   [bold]docker logs -f {container.short_id}[/bold]")
        console.print(
            "[dim](For integrated monitoring, configure your Docker log driver for ELK/Splunk.)[/dim]"
        )

    except docker.errors.DockerException as e:
        console.print(
            "[bold red]Docker Error:[/bold red] Could not connect to the Docker daemon. Is it running?"
        )
        console.print(f"   Details: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1)