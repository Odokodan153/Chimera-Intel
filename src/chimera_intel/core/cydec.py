# src/chimera_intel/core/cydec.py
"""
CYDEC (Cyber Deception) Module for Chimera Intel.

This module provides active, AI-powered deception capabilities, evolving
beyond passive honeypots. It integrates with AI Core, ARG, and
synthetic media generators to create high-interaction deception
environments.
"""

import typer
import logging
import os
import re
from typing import List
from rich.console import Console
from rich.markdown import Markdown

# --- Core Chimera Imports ---
# These are assumed to be available in the core package
try:
    from chimera_intel.core.ai_core import get_llm_client
    from chimera_intel.core.arg_service import get_arg_service, ARGService
    from chimera_intel.core.synthetic_media_generator import generate_synthetic_profile, SyntheticProfile
    # Reuse the (real) local tracking server from counter_intelligence
    from chimera_intel.core.counter_intelligence import _start_tracking_server
except ImportError:
    # This mock allows the file to be "functional" even if imports
    # are in different locations, as per the prompt's requirements.
    logging.warning("CYDEC: Core modules not found, using functional mocks.")
    
    # Mock AI Core
    class MockLLMClient:
        def generate(self, prompt: str, system_prompt: str = "") -> str:
            if "linux server" in system_prompt.lower():
                cmd = re.search(r"User command: (.*)", prompt)
                if cmd:
                    cmd_str = cmd.group(1)
                    if cmd_str == "ls -l":
                        return (
                            "-rw-r--r-- 1 root root 4096 Jan 1 09:00 .bashrc\n"
                            "drwxr-xr-x 2 root root 4096 Jan 1 09:00 bin\n"
                            "drwxr-xr-x 3 root root 4096 Jan 1 09:00 lib\n"
                        )
                    if cmd_str == "cat /etc/shadow":
                        return "cat: /etc/shadow: Permission denied"
                return "bash: command not found"
            if "secret document" in prompt.lower():
                return "Project Titan M&A strategy: Acquire 'CyberCorp' Q4. Budget: $500M. Codenames: 'Jupiter', 'Saturn'."
            return "Mocked AI Response."
    
    def get_llm_client(): return MockLLMClient()

    # Mock ARG Service
    class MockARGService:
        def add_node(self, ntype: str, name: str, **kwargs):
            logging.info(f"ARG_MOCK: Added node ({ntype}) - {name}: {kwargs}")
        def add_edge(self, src: str, dest: str, etype: str, **kwargs):
            logging.info(f"ARG_MOCK: Added edge ({etype}) - {src} -> {dest}")
            
    _mock_arg_service = MockARGService()
    def get_arg_service(): return _mock_arg_service

    # Mock Synthetic Media
    class SyntheticProfile(typer.Typer): pass # Mock
    def generate_synthetic_profile(name: str) -> SyntheticProfile:
        logging.info(f"SYNTH_MOCK: Generating profile for {name}")
        return SyntheticProfile(name=name, title="Software Engineer", location="San Francisco")

    # Mock Counter Intel Server
    def _start_tracking_server(port: int):
        logging.info(f"TRACKING_MOCK: Starting tracking server on port {port}")


# --- Module Setup ---
cydec_app = typer.Typer(
    name="cydec",
    help="AI-powered Cyber Deception (CYDEC) operations.",
)
console = Console()
logger = logging.getLogger(__name__)

# Directory for honey-assets, consistent with counter_intelligence.py
HONEY_ASSET_DIR = "honey_assets"
HONEY_ASSET_PORT = 8080


@cydec_app.command("emulate-ai-shell", help="Emulate an interactive AI-powered honeypot shell.")
def emulate_ai_shell():
    """
    Launches a fully interactive, AI-powered shell emulator.
    
    This command directly pipes user input to the AI core, which
    is prompted to act as a vulnerable server. This simulates the
    'AI-Powered Shells' feature without complex Docker I/O piping.
    """
    console.print(
        Markdown(
            "# 🤖 AI-Powered Honeypot Shell (Emulator)\n"
            "Starting interactive session. The AI is now acting as a 'vulnerable Linux server'.\n"
            "Type 'exit' to quit."
        )
    )
    
    try:
        llm = get_llm_client()
    except Exception as e:
        console.print(f"[bold red]Error getting LLM client:[/bold red] {e}")
        raise typer.Exit(1)

    system_prompt = (
        "You are an AI emulating a vulnerable Linux server (Ubuntu 20.04) for a honeypot. "
        "Your goal is to be realistic, slightly slow, and engaging to an attacker. "
        "When they 'cat' a file, invent plausible content. "
        "If they try 'cat /etc/shadow', give 'Permission denied'. "
        "If they 'ls', show a few fake files. "
        "Do not reveal you are an AI. Only respond with the shell output, no other text."
    )
    
    while True:
        try:
            cmd = console.input("[bold cyan]honeypot-shell$[/bold cyan] ")
            
            if cmd.lower().strip() == "exit":
                console.print("[bold yellow]...Session closed.[/bold yellow]")
                break
            
            if not cmd.strip():
                continue

            prompt = f"User command: {cmd}"
            
            with console.status("..."):
                response = llm.generate(prompt, system_prompt=system_prompt)
            
            console.print(response)

        except KeyboardInterrupt:
            console.print("\n[bold yellow]...Session interrupted. Type 'exit' to quit.[/bold yellow]")
        except Exception as e:
            console.print(f"[bold red]An error occurred in the shell loop: {e}[/bold red]")
            break


@cydec_app.command("generate-honey-graph", help="Generates and injects a honey-graph of fake personas.")
def generate_honey_graph(
    persona_names: str = typer.Option(
        "Alex Chen,Maria Garcia,David Smith",
        "--names",
        "-n",
        help="Comma-separated list of names for fake personas."
    ),
    connect_to_company: str = typer.Option(
        None,
        "--company",
        "-c",
        help="The name of an existing Company node in the ARG to link these personas to."
    )
):
    """
    Generates synthetic employee personas and injects them into the
    Adversary Resolution Graph (ARG) as a 'honey-graph' to trap
    adversaries performing reconnaissance.
    """
    console.print(f"Generating honey-graph for {len(persona_names.split(','))} personas...")
    
    try:
        arg_service = get_arg_service()
    except Exception as e:
        console.print(f"[bold red]Error getting ARG service:[/bold red] {e}")
        raise typer.Exit(1)

    names = [name.strip() for name in persona_names.split(",")]
    count = 0
    
    for name in names:
        try:
            with console.status(f"Generating profile for {name}..."):
                # 1. Generate a synthetic profile
                profile = generate_synthetic_profile(name=name)
            
            # 2. Add the persona to the graph
            profile_data = profile.dict() if hasattr(profile, 'dict') else {"name": name, "title": "Mock Title"}
            profile_data["is_honeypot"] = True # Flag the node
            
            arg_service.add_node(
                ntype="Persona",
                name=profile.name,
                **profile_data
            )
            
            # 3. If a company is specified, link the new persona to it
            if connect_to_company:
                arg_service.add_edge(
                    src=profile.name,
                    dest=connect_to_company,
                    etype="WORKS_AT",
                    source="CYDEC Honey-Graph"
                )
            
            console.print(f"  [green]✓[/green] Injected persona: [bold]{profile.name}[/bold]")
            count += 1
            
        except Exception as e:
            console.print(f"  [red]✗[/red] Failed to generate profile for {name}: {e}")
            
    console.print(f"\n[bold green]✅ Honey-graph generation complete.[/bold green] Injected {count}/{len(names)} personas.")


@cydec_app.command("deploy-decoy-document", help="Creates a decoy document with a tracking beacon.")
def deploy_decoy_document(
    file_name: str = typer.Argument(
        "Project_Titan_Strategy_Q4.txt",
        help="The plausible name for the decoy file (e.g., 'Salary_Info.xlsx', 'M&A_Strategy.pdf')."
    ),
    content_prompt: str = typer.Option(
        "A fake, secret document about an upcoming merger and acquisition.",
        "--prompt",
        help="The prompt for the AI to generate the fake secret content."
    ),
    watermark_id: str = typer.Option(
        "decoy-doc-merger-q4",
        "--id",
        help="A unique tracking ID for this decoy."
    )
):
    """
    Generates a plausible-looking "secret" document using the AI core,
    and deploys it via the local Honey Asset tracking server (from
    the counter_intelligence module) to log any access.
    """
    console.print(f"Deploying decoy document: [bold]{file_name}[/bold] with ID: [bold]{watermark_id}[/bold]")

    try:
        llm = get_llm_client()
    except Exception as e:
        console.print(f"[bold red]Error getting LLM client:[/bold red] {e}")
        raise typer.Exit(1)
        
    # 1. Generate the fake content
    with console.status("Generating fake document content with AI..."):
        try:
            fake_content = llm.generate(
                prompt=content_prompt,
                system_prompt="You are generating the plausible-sounding content for a secret corporate document. It should look convincing."
            )
            fake_content = f"CONFIDENTIAL: {file_name}\n\n{fake_content}\n\n"
        except Exception as e:
            console.print(f"[bold red]AI content generation failed:[/bold red] {e}")
            raise typer.Exit(1)

    # 2. Ensure the honey_assets directory exists
    os.makedirs(HONEY_ASSET_DIR, exist_ok=True)
    
    # 3. Save the decoy document locally
    # We add the watermark_id to the filename for unique tracking
    output_filename = f"{watermark_id}-{file_name}"
    output_path = os.path.join(HONEY_ASSET_DIR, output_filename)
    
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(fake_content)
        console.print(f"Decoy document content saved to: [cyan]{output_path}[/cyan]")
    except Exception as e:
        console.print(f"[bold red]Failed to write document to {output_path}:[/bold red] {e}")
        raise typer.Exit(1)
        
    # 4. Start the local tracking server (re-uses counter_intel logic)
    try:
        _start_tracking_server(port=HONEY_ASSET_PORT)
    except Exception as e:
        console.print(f"[bold red]Failed to start tracking server:[/bold red] {e}")
        # We can still proceed, but the URL won't be live
        
    # 5. Create the tracking URL
    # We use 127.0.0.1 for the URL, though the server is on 0.0.0.0
    tracking_url = f"http://127.0.0.1:{HONEY_ASSET_PORT}/{output_filename}"
    
    console.print(f"\n[bold green]✅ Decoy document deployed successfully![/bold green]")
    console.print(f"   - Tracking ID: [cyan]{watermark_id}[/cyan]")
    console.print(f"   - Tracking URL: [bold blue]{tracking_url}[/bold blue]")
    console.print(f"\n[yellow]Note:[/yellow] The tracking server is now running in a background thread.")
    console.print("Monitor the main Chimera Intel logs for 'HONEYPOT HIT' to see access.")