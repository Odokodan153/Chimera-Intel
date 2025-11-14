"""
Adversary Simulation (CALDERA Integration)

This module acts as the "hands-on" execution arm for the purple_team and 
red_team modules. It translates AI-generated operational plans into
MITRE CALDERA operations, executes them against provisioned targets,
and aggregates the results for automated gap analysis.
"""

import typer
import asyncio
import json
import httpx
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from .logger_config import get_logger
from .config_loader import API_KEYS, get_config
from .utils import console
from .gemini_client import GeminiClient

# --- Schemas ---
# Assumed imports from src.chimera_intel.core.schemas
try:
    from .schemas import RedTeamPlan, EmulationLabTarget
except ImportError:
    # Define stubs if not present
    class RedTeamPlan(BaseModel):
        target_id: str
        ttps: List[str] = []
        narrative: str

    class EmulationLabTarget(BaseModel):
        target_id: str
        ip_address: str
        hostname: str
        credentials: Optional[Dict[str, str]] = None
        metadata: Dict[str, Any] = {}
from .schemas import AdversarySimulationResult, ExecutedStep

logger = get_logger(__name__)

app = typer.Typer(
    name="adversary-sim",
    help="Adversary Simulation engine (MITRE CALDERA integration).",
)

class CalderaClient:
    """
    A client for interacting with the MITRE CALDERA API.
    
    Assumes CALDERA_URL and CALDERA_API_KEY are in the config.
    """
    def __init__(self):
        try:
            self.server_url = get_config("caldera.url")
            self.api_key = API_KEYS.caldera_api_key
        except Exception:
            logger.error("CALDERA_URL or CALDERA_API_KEY not configured.")
            self.server_url = None
            self.api_key = None
            
        if not self.server_url or not self.api_key:
            raise ValueError("CALDERA_URL and CALDERA_API_KEY must be set.")

        self.base_headers = {
            "KEY": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _request(
        self, method: str, endpoint: str, payload: Optional[Dict] = None
    ) -> Dict:
        async with httpx.AsyncClient(
            base_url=self.server_url, headers=self.base_headers, verify=False
        ) as client:
            try:
                if payload:
                    response = await client.request(
                        method, endpoint, json=payload
                    )
                else:
                    response = await client.request(method, endpoint)
                
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                logger.error(f"CALDERA API Error: {e.response.status_code} {e.response.text}")
                return {"error": str(e), "details": e.response.text}
            except httpx.RequestError as e:
                logger.error(f"CALDERA Request Error: {e}")
                return {"error": str(e)}

    async def get_all_abilities(self) -> List[Dict]:
        """Fetches all available abilities from CALDERA."""
        return await self._request("GET", "/api/v2/abilities")

    async def create_adversary(
        self, name: str, description: str, ability_ids: List[str]
    ) -> Dict:
        """Creates a new adversary profile."""
        payload = {
            "name": name,
            "description": description,
            "atomic_ordering": ability_ids,
        }
        return await self._request("POST", "/api/v2/adversaries", payload=payload)

    async def create_and_run_operation(
        self, name: str, adversary_id: str, agent_paw: str
    ) -> Dict:
        """Creates a new operation and sets it to 'running'."""
        payload = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "agents": [{"paw": agent_paw}],
            "state": "running",
            "autonomous": True
        }
        return await self._request("POST", "/api/v2/operations", payload=payload)

    async def get_operation_report(self, op_id: str) -> Dict:
        """Fetches the full report for a given operation."""
        return await self._request("GET", f"/api/v2/operations/{op_id}")

    async def get_operation_links(self, op_id: str) -> List[Dict]:
        """Fetches the links (executed steps) for an operation."""
        return await self._request("GET", f"/api/v2/operations/{op_id}/links")

    async def poll_for_completion(self, op_id: str, timeout: int = 300) -> str:
        """Polls an operation until it's finished or times out."""
        start_time = asyncio.get_event_loop().time()
        while True:
            op = await self.get_operation_report(op_id)
            if op.get("state") in ["finished", "out_of_time"]:
                return "completed"
            if (asyncio.get_event_loop().time() - start_time) > timeout:
                return "timeout"
            
            await asyncio.sleep(10) # Poll every 10 seconds


# --- Feature 1: Plan Translator ---

async def _translate_plan_to_abilities(
    plan: RedTeamPlan, all_abilities: List[Dict]
) -> List[str]:
    """
    Uses AI to translate a high-level plan into a sequence of
    CALDERA ability IDs.
    """
    ai_client = GeminiClient()
    
    # Prune abilities to only include key info for the prompt
    abilities_context = [
        {
            "id": a["ability_id"],
            "name": a["name"],
            "description": a["description"],
            "ttp": a.get("tactic", "unknown"),
        }
        for a in all_abilities
    ]

    prompt = f"""
    You are a red team automation specialist. Your task is to translate a
    high-level operational plan into a specific sequence of CALDERA
    ability IDs.
    
    Given the plan narrative, the list of target TTPs, and a list of
    all available CALDERA abilities, select the ability IDs that
    best achieve the plan's objectives *in the correct order*.

    High-Level Plan:
    {plan.model_dump_json(indent=2)}

    Available CALDERA Abilities (Partial List):
    {json.dumps(abilities_context[:100], indent=2)} 
    
    Return ONLY a valid JSON list of strings, where each string is
    an ability ID from the "Available Abilities" list.

    Example Output:
    ["c2c26f6d-b003-4e41-b248-cf2d8f588a8d", "a01a0110-3111-464e-b5c9-159c402b11b1"]
    """
    
    try:
        response_text = ai_client.generate_response(prompt)
        # Clean and parse the JSON response
        json_str = response_text.strip().lstrip("```json").rstrip("```")
        ability_ids = json.loads(json_str)
        
        if not isinstance(ability_ids, list) or not all(isinstance(i, str) for i in ability_ids):
            raise ValueError("AI did not return a list of strings.")

        return ability_ids
    except Exception as e:
        logger.error(f"Failed to translate plan to abilities: {e}")
        return []

# --- Feature 3: Results Aggregation ---

def _parse_caldera_report(
    op_report: Dict, op_links: List[Dict], target_paw: str
) -> AdversarySimulationResult:
    """
    Parses the raw CALDERA operation and link data into our
    standardized AdversarySimulationResult schema.
    """
    steps = []
    for link in op_links:
        # Status 0 = success, 1 = error, -3 = timeout
        status_map = {0: "success", 1: "failure", -3: "timeout"}
        status_code = link.get("status", -2) # -2 = pending
        
        steps.append(
            ExecutedStep(
                ability_id=link["ability"]["ability_id"],
                ability_name=link["ability"]["name"],
                ttp=link["ability"].get("tactic"),
                command=link.get("command", "N/A"),
                status=status_map.get(status_code, "pending"),
                output=link.get("output", "N/A"),
                timestamp=link.get("decide", "N/A"),
            )
        )
    
    return AdversarySimulationResult(
        operation_id=op_report["id"],
        operation_name=op_report["name"],
        target_paw=target_paw,
        status=op_report.get("state", "unknown"),
        executed_steps=steps,
    )

# --- Feature 2: Automated Execution (Main Orchestrator) ---

async def run_simulation(
    plan: RedTeamPlan, target: EmulationLabTarget
) -> AdversarySimulationResult:
    """
    The main orchestrator function.
    
    1.  Translates the AI-generated plan into CALDERA abilities.
    2.  Creates a CALDERA adversary profile.
    3.  Launches the operation against the provisioned target.
    4.  Polls for completion.
    5.  Aggregates and returns the results.
    """
    console.print(f"[bold cyan]Starting Adversary Simulation for target: {target.target_id}[/bold cyan]")
    
    # Critical Prerequisite: The emulation_lab must deploy the
    # CALDERA agent and provide its "paw" (agent ID) in the metadata.
    target_paw = target.metadata.get("caldera_paw")
    if not target_paw:
        msg = f"Target {target.target_id} is not CALDERA-enabled. 'caldera_paw' not found in metadata."
        logger.error(msg)
        return AdversarySimulationResult(
            operation_id="", operation_name="", target_paw="", status="failed",
            error_message=msg
        )

    try:
        client = CalderaClient()
        
        # 1. Translate Plan
        console.print("[cyan]Translating AI plan to CALDERA abilities...[/cyan]")
        all_abilities = await client.get_all_abilities()
        ability_ids = await _translate_plan_to_abilities(plan, all_abilities)
        if not ability_ids:
            raise Exception("AI failed to translate plan to abilities.")
        console.print(f"[green]Plan translated to {len(ability_ids)} abilities.[/green]")

        # 2. Create Adversary Profile
        adv_name = f"adv-{plan.target_id}-{asyncio.get_event_loop().time()}"
        adversary = await client.create_adversary(
            name=adv_name,
            description=f"Adversary for plan: {plan.narrative[:50]}",
            ability_ids=ability_ids
        )
        adversary_id = adversary.get("adversary_id")
        if not adversary_id:
            raise Exception(f"Failed to create adversary: {adversary.get('error')}")
        
        # 3. Launch Operation
        op_name = f"op-{plan.target_id}-{asyncio.get_event_loop().time()}"
        console.print(f"[cyan]Launching CALDERA operation '{op_name}' against paw '{target_paw}'...[/cyan]")
        operation = await client.create_and_run_operation(
            name=op_name,
            adversary_id=adversary_id,
            agent_paw=target_paw
        )
        op_id = operation.get("id")
        if not op_id:
            raise Exception(f"Failed to create operation: {operation.get('error')}")

        # 4. Poll for Completion
        console.print(f"[cyan]Operation {op_id} running. Polling for completion...[/cyan]")
        status = await client.poll_for_completion(op_id)
        console.print(f"[green]Operation {op_id} finished with status: {status}[/green]")

        # 5. Aggregate Results
        op_report = await client.get_operation_report(op_id)
        op_links = await client.get_operation_links(op_id)
        
        return _parse_caldera_report(op_report, op_links, target_paw)

    except Exception as e:
        logger.error(f"Adversary simulation failed: {e}", exc_info=True)
        return AdversarySimulationResult(
            operation_id="", operation_name="", target_paw=target_paw,
            status="failed", error_message=str(e)
        )


# --- CLI Commands ---

@app.command("run-test", help="Run a test simulation with specific TTPs and a target paw.")
def run_simulation_cli(
    target_paw: str = typer.Argument(..., help="The 'paw' ID of the target CALDERA agent."),
    ttp: List[str] = typer.Option(..., "--ttp", help="A TTP to execute (e.g., T1059.003). Can be used multiple times.")
):
    """
    This CLI command is a test harness. It creates a simple plan and
    executes it against a known, running agent.
    """
    console.print(f"[bold]Running Test Simulation[/bold]")
    console.print(f"  Target Paw: {target_paw}")
    console.print(f"  TTPs: {', '.join(ttp)}")
    
    # 1. Create a stub plan
    plan = RedTeamPlan(
        target_id="cli-test",
        ttps=ttp,
        narrative=f"CLI test to execute {', '.join(ttp)}"
    )
    
    # 2. Create a stub target
    target = EmulationLabTarget(
        target_id="cli-test-target",
        ip_address="127.0.0.1",
        hostname="test-host",
        metadata={"caldera_paw": target_paw}
    )
    
    # 3. Run the simulation
    result = asyncio.run(run_simulation(plan, target))
    
    # 4. Print results
    console.print("\n--- Simulation Result ---")
    console.print(result.model_dump_json(indent=2))
    if result.status == "failed":
        raise typer.Exit(code=1)

@app.command("list-abilities", help="List all available CALDERA abilities.")
def list_abilities_cli():
    client = CalderaClient()
    abilities = asyncio.run(client.get_all_abilities())
    
    console.print(f"[bold]Found {len(abilities)} CALDERA Abilities:[/bold]")
    for ab in abilities:
        console.print(f"- [green]{ab['name']}[/green] (ID: {ab['ability_id']})")
        console.print(f"  TTP: {ab.get('tactic', 'N/A')}")
        console.print(f"  Desc: {ab['description'][:100]}...")

@app.command("get-report", help="Get the full report for a specific operation ID.")
def get_report_cli(operation_id: str):
    client = CalderaClient()
    
    async def fetch():
        op = await client.get_operation_report(operation_id)
        links = await client.get_operation_links(operation_id)
        return op, links

    op, links = asyncio.run(fetch())
    
    # Manually create a dummy paw for the parser
    target_paw = op.get("agents", [{}])[0].get("paw", "unknown")
    
    result = _parse_caldera_report(op, links, target_paw)
    console.print(result.model_dump_json(indent=2))