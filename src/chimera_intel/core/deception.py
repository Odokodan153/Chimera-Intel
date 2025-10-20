"""
Deception & Honeypot Operations Module for Chimera Intel.
"""

import typer
import docker
from rich.console import Console

console = Console()

deception_app = typer.Typer(
    name="deception",
    help="Active defense through deception and honeypot operations.",
)

# A map of supported honeypot types to their Docker images
HONEYPOT_IMAGES = {
    "ssh": "cowrie/cowrie",
    "telnet": "cowrie/cowrie",
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
    image_name = HONEYPOT_IMAGES.get(honeypot_type)

    if not image_name:
        console.print(
            f"[bold red]Error:[/bold red] Honeypot type '{honeypot_type}' is not supported. Supported types: {list(HONEYPOT_IMAGES.keys())}"
        )
        raise typer.Exit(code=1)
    internal_port = 2222 if honeypot_type == "ssh" else 2223

    console.print(
        f"Deploying '{honeypot_type}' honeypot using image '{image_name}' on port {port}..."
    )

    try:
        client = docker.from_env()
        # Test if Docker daemon is running
        client.ping()

        console.print(f"Pulling image '{image_name}'... (This may take a moment)")
        client.images.pull(image_name)

        container = client.containers.run(
            image=image_name,
            detach=True,
            ports={f"{internal_port}/tcp": port},
            name=f"chimera-honeypot-{honeypot_type}-{port}",
        )

        console.print("\n[bold green]✅ Honeypot deployed successfully![/bold green]")
        console.print(
            f"   - Container Name: [cyan]chimera-honeypot-{honeypot_type}-{port}[/cyan]"
        )
        console.print(f"   - Container ID: [cyan]{container.short_id}[/cyan]")
        console.print(f"   - Exposed Port: Host {port} -> Container {internal_port}")
        console.print("\nTo view attacker interactions, run:")
        console.print(f"   [bold]docker logs -f {container.short_id}[/bold]")
    except docker.errors.DockerException as e:
        console.print(
            "[bold red]Docker Error:[/bold red] Could not connect to the Docker daemon. Is it running?"
        )
        console.print(f"   Details: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1)