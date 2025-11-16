"""
Active Psychological Intelligence (PSYINT) Orchestrator.

This module is the "Red Team" counterpart to cognitive_warfare_engine.py.
It focuses on the *active deployment* of influence campaigns and psychological
operations, orchestrating other modules to achieve this.

**HIGH-RISK MODULE**: All 'execute' actions are heavily gated by
action_governance.py and human_review_service.py.
"""

import typer
import json
import logging
from typing import List, Optional, Dict
from .schemas import (
    PsyintCampaignConfig,
    PsyintCampaignPlan,
    CampaignExecutionResult,
)
import asyncio
from .action_governance import (
    run_pre_flight_checks,
    ACTION_REGISTRY,
    ActionMetadata,
    ActionRiskLevel,
)
from .human_review_service import HumanReviewService
from .ai_core import generate_swot_from_data
from .config_loader import API_KEYS
from .utils import console
from .schemas import SyntheticImageResult
from .synthetic_media_generator import generate_synthetic_image_with_ai
from .social_osint import find_target_audiences_by_description
from .narrative_analyzer import track_narrative_gnews

logger = logging.getLogger(__name__)

# --- Governance Registration ---

ACTION_NAME = "psyint:deploy-campaign"


def register_psyint_actions():
    """
    Registers the high-risk PSYINT actions with the Action Governance registry.
    This is called by the plugin loader.
    """
    if ACTION_NAME not in ACTION_REGISTRY:
        ACTION_REGISTRY[ACTION_NAME] = ActionMetadata(
            description="Deploys an active PSYINT campaign (simulation). This is a high-risk, consent-gated action.",
            risk_level=ActionRiskLevel.AGGRESSIVE,
            legal_metadata="Requires explicit, multi-level approval and signed Rules of Engagement (RoE).",
            consent_required=True,
        )
        logger.info(f"Registered governance for action: {ACTION_NAME}")


# --- Core Orchestrator Class ---


class ActivePsyintOrchestrator:
    """Orchestrates the planning and execution of PSYINT campaigns."""

    def __init__(
        self,
        config: PsyintCampaignConfig,
        consent_file: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.config = config
        self.consent_file = consent_file
        self.api_key = api_key or API_KEYS.google_api_key
        self.plan: Optional[PsyintCampaignPlan] = None

    async def _generate_narrative_variants(self) -> Dict[str, str]:
        """(REAL) Uses ai_core to generate A/B test narrative variants."""
        console.print("  - Generating A/B narrative variants...")
        if not self.api_key:
            logger.warning("No API key found. Using fallback for narrative variants.")
            return {
                "variant_a": self.config.base_narrative + " (Mock A)",
                "variant_b": self.config.base_narrative + " (Mock B)",
            }

        prompt = f"""
        You are a psychological operations planner.
        Given a base narrative, generate two alternative versions (A/B test)
        that are subtly different but aim for the same goal.
        
        Goal: {self.config.narrative_goal}
        Base Narrative: {self.config.base_narrative}
        
        Return a single JSON object with two keys: "variant_a" and "variant_b".
        Return ONLY the valid JSON object.
        """
        try:
            ai_result = await generate_swot_from_data(prompt, self.api_key)
            if ai_result.error:
                raise Exception(ai_result.error)
            
            json_text = ai_result.analysis_text.strip().lstrip("```json").rstrip("```")
            data = json.loads(json_text)
            return {
                "variant_a": data.get("variant_a", self.config.base_narrative + " (Fallback A)"),
                "variant_b": data.get("variant_b", self.config.base_narrative + " (Fallback B)"),
            }
        except Exception as e:
            logger.error(f"Failed to generate narrative variants: {e}")
            return {
                "variant_a": self.config.base_narrative + " (Error A)",
                "variant_b": self.config.base_narrative + " (Error B)",
            }

    async def _identify_target_audiences(self) -> List[str]:
        """(REAL) Uses social_osint to find target audiences."""
        console.print("  - Identifying target audiences...")
        try:
            # Call the REAL async function
            audiences = await find_target_audiences_by_description(
                self.config.target_audience_desc, self.api_key
            )
            return audiences
        except Exception as e:
            logger.error(f"Failed to identify target audiences: {e}")
            return [f"error_audience_for_{self.config.target_audience_desc[:20]}"]

    async def _generate_synthetic_assets(self) -> List[str]:
        """(REAL) Uses synthetic_media_generator to create assets."""
        console.print("  - Generating synthetic media assets...")
        assets = []
        prompts = [
            f"An image representing the narrative: {self.config.base_narrative}",
            f"An image for the goal: {self.config.narrative_goal}",
        ]
        
        if not self.api_key:
            logger.warning("No API key. Returning mock asset paths.")
            return [f"mock_asset_for_{p[:20]}.jpg" for p in prompts]
            
        for prompt in prompts:
            try:
                # Call the REAL async function
                result: SyntheticImageResult = await generate_synthetic_image_with_ai(
                    prompt, self.api_key
                )
                if result.image_url:
                    assets.append(result.image_url)
                else:
                    assets.append("error_generating_asset.jpg")
            except Exception as e:
                logger.error(f"Failed to generate synthetic asset for prompt '{prompt}': {e}")
                assets.append("error_generating_asset.jpg")
        return assets

    async def plan_campaign(self) -> PsyintCampaignPlan:
        """
        (LOW-RISK) Orchestrates the planning phase of the campaign.
        Generates assets and plans but does *not* deploy.
        """
        console.print("[bold cyan]Planning PSYINT Campaign...[/bold cyan]")
        
        variants = await self._generate_narrative_variants()
        audiences = await self._identify_target_audiences()
        assets = await self._generate_synthetic_assets()
        
        self.plan = PsyintCampaignPlan(
            config=self.config,
            narrative_variants=variants,
            identified_audiences=audiences,
            synthetic_assets=assets,
        )
        
        console.print("[bold green]Campaign plan generated.[/bold green]")
        return self.plan

    def execute_campaign(self) -> CampaignExecutionResult:
        """
        (HIGH-RISK) Executes the planned campaign.
        This action is gated by action_governance.py and human_review_service.py.
        """
        if not self.plan:
            return CampaignExecutionResult(status="ERROR", message="No campaign plan found. Run 'plan' first.")

        console.print(
            f"[bold red]Attempting HIGH-RISK action: {ACTION_NAME}[/bold red]"
        )
        
        # 1. Governance Integration: Run Pre-Flight Checks
        is_authorized = run_pre_flight_checks(
            action_name=ACTION_NAME,
            target=self.config.target_audience_desc,
            consent_file=self.consent_file,
        )

        if not is_authorized:
            # 2. Governance Integration: Failed checks, submit for Human Review
            console.print(
                "[bold yellow]Pre-flight checks FAILED. Submitting for human review...[/bold yellow]"
            )
            try:
                review_service = HumanReviewService()
                request = review_service.submit_for_review(
                    user="psyint_orchestrator",
                    action_name=ACTION_NAME,
                    target=self.config.target_audience_desc,
                    provenance=self.plan.model_dump(),
                    justification=f"Automated request for PSYINT campaign: {self.config.narrative_goal}"
                )
                return CampaignExecutionResult(
                    status="PENDING_REVIEW",
                    message="Action failed pre-flight checks and was submitted for human review.",
                    review_request_id=request.id
                )
            except Exception as e:
                logger.error(f"Failed to submit for human review: {e}")
                return CampaignExecutionResult(status="ERROR", message=f"Pre-flight checks failed and review submission also failed: {e}")

        # 3. Authorized: Proceed with (simulated) execution
        console.print(
            "[bold green]All pre-flight checks passed. Action is authorized.[/bold green]"
        )
        console.print(
            f"--- [bold]SIMULATING CAMPAIGN DEPLOYMENT[/bold] ---"
        )
        
        # A/B Testing Simulation
        for variant_name, narrative in self.plan.narrative_variants.items():
            console.print(f"  - Deploying [yellow]{variant_name}[/yellow] to '{self.config.target_platforms[0]}'")
            console.print(f"    - Message: '{narrative[:50]}...'")
            
        console.print(f"  - Deploying assets: {self.plan.synthetic_assets}")
        console.print(f"  - Targeting audiences: {self.plan.identified_audiences}")

        # 4. Orchestration: Monitor campaign effectiveness
        console.print("\n[bold cyan]Simulating campaign monitoring...[/bold cyan]")
        
        # Call the REAL synchronous function
        report = track_narrative_gnews(self.config.base_narrative)
        
        monitoring_summary = {
            "monitored_query": self.config.base_narrative,
            "simulated_hits": len(report.articles),
            "sample_hit": report.articles[0] if report.articles else "No hits",
        }

        console.print(f"--- [bold]SIMULATION COMPLETE[/bold] ---")

        return CampaignExecutionResult(
            status="SIMULATED_EXECUTION",
            message="Campaign was successfully simulated.",
            monitoring_report=monitoring_summary,
        )


# --- Typer CLI Application ---

psyint_app = typer.Typer(
    name="psyint",
    help="Active Psychological Intelligence (PSYINT) & Influence Operations.",
)

@psyint_app.command()
def plan(
    narrative_goal: str = typer.Option(
        ..., "--goal", help="The objective of the narrative."
    ),
    base_narrative: str = typer.Option(
        ..., "--narrative", help="The core message to deploy."
    ),
    target_audience: str = typer.Option(
        ..., "--audience", help="Description of the target audience."
    ),
    platforms: str = typer.Option(
        "twitter,forums", "--platforms", help="Comma-separated list of target platforms."
    ),
    out_file: str = typer.Option(
        "campaign_plan.json",
        "--out",
        "-o",
        help="Output file for the generated campaign plan.",
    ),
):
    """
    (LOW-RISK) Plan an active PSYINT campaign.
    Generates A/B test narratives, identifies audiences, and creates
    synthetic assets. Saves the plan to a JSON file.
    """
    config = PsyintCampaignConfig(
        narrative_goal=narrative_goal,
        base_narrative=base_narrative,
        target_audience_desc=target_audience,
        target_platforms=platforms.split(","),
    )
    
    orchestrator = ActivePsyintOrchestrator(config=config)
    
    # Run async planning
    async def _plan():
        return await orchestrator.plan_campaign()
    
    plan_result = asyncio.run(_plan())

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(plan_result.model_dump_json(indent=2))
        
    console.print(f"[bold green]Campaign plan saved to {out_file}[/bold green]")
    console.print_json(data=plan_result.model_dump())


@psyint_app.command()
def execute(
    plan_file: str = typer.Argument(
        ..., help="Path to the 'campaign_plan.json' file generated by 'plan'."
    ),
    consent_file: Optional[str] = typer.Option(
        None, "--consent", help="Path to signed consent file (Rules of Engagement). REQUIRED for execution."
    ),
):
    """
    (HIGH-RISK) Execute a planned PSYINT campaign (simulation).
    This action is gated by Action Governance and Human Review.
    It requires a --consent file to proceed.
    """
    try:
        with open(plan_file, "r", encoding="utf-8") as f:
            plan_data = json.load(f)
        
        # Re-load the plan and config from the file
        plan = PsyintCampaignPlan(**plan_data)
        config = plan.config
        
        orchestrator = ActivePsyintOrchestrator(config=config, consent_file=consent_file)
        orchestrator.plan = plan # Inject the loaded plan
        
        result = orchestrator.execute_campaign()
        
        console.print_json(data=result.model_dump())
        
        if result.status == "PENDING_REVIEW":
            console.print(f"[bold yellow]ACTION PENDING: Review ID {result.review_request_id}[/bold yellow]")
        elif result.status == "ERROR":
            console.print(f"[bold red]EXECUTION FAILED: {result.message}[/bold red]")
            raise typer.Exit(code=1)
        else:
            console.print(f"[bold green]EXECUTION SIMULATED: {result.message}[/bold green]")
            
    except FileNotFoundError:
        console.print(f"[bold red]Error: Plan file not found at {plan_file}[/bold red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    psyint_app()