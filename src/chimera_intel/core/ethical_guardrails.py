# src/chimera_intel/core/ethical_guardrails.py

"""
Ethical Guardrails & Policy Engine for Synthetic Media.

This module implements the core policy logic for Req 9, using the
local_db_service as its persistent datastore.

It also now defines its own Typer app for CLI policy checks.
"""

from .schemas import (
    SubjectProfile,
    SubjectSensitivity,
    AllowedUseCase,
    GenerationType,
    RiskLevel,
    DisallowedUseCaseError
)
import logging
import typer  
import uuid   
from rich.console import Console  
from typing import Optional
# --- Database Imports ---
from .local_db_service import get_scans_by_target, save_scan_to_db

# --- Constants ---
SUBJECT_PROFILE_MODULE_NAME = "subject_profile"
logger = logging.getLogger(__name__)

# --- Database Interaction Functions ---

def save_subject_profile(profile: SubjectProfile) -> None:
    """Saves a SubjectProfile to the local database."""
    try:
        save_scan_to_db(
            target=profile.display_name.lower(), # Use lower-case name for consistent lookups
            module=SUBJECT_PROFILE_MODULE_NAME,
            data=profile.model_dump(),
            scan_id=profile.subject_id
        )
        logger.info(f"Saved subject profile: {profile.display_name}")
    except Exception as e:
        logger.error(f"Failed to save subject profile {profile.display_name}: {e}")
        raise

def get_subject_profile_from_db(subject_name: str) -> Optional[SubjectProfile]:
    """
    Retrieves a subject's profile from the database by their display name.
    """
    try:
        # Query DB for a profile matching the name (as target)
        results = get_scans_by_target(
            target=subject_name.lower(),
            module=SUBJECT_PROFILE_MODULE_NAME
        )
        if results:
            # Return the first one found
            return SubjectProfile(**results[0])
    except Exception as e:
        logger.error(f"Error retrieving profile for {subject_name}: {e}")
    
    return None


# --- Main Service Class ---

class EthicalGuardrails:
    """
    Implements the policy checks for synthetic media generation
    by querying the local_db_service.
    """

    def get_subject_profile(self, subject_name: str) -> SubjectProfile:
        """
        Retrieves a subject's profile from the database.
        If not found, returns a default "general adult" profile.
        """
        if not subject_name:
             # This is a stock person
            return SubjectProfile(
                subject_id="stock-000",
                display_name="Stock Person",
                sensitivity=SubjectSensitivity.STOCK_PERSON
            )

        profile = get_subject_profile_from_db(subject_name)
        
        if profile:
            return profile
        
        # Default profile for unknown, consenting adults
        logger.warning(f"No profile found for '{subject_name}'. Defaulting to GENERAL_ADULT.")
        return SubjectProfile(
            subject_id=f"gen-hash-{hash(subject_name)}", # non-persistent ID
            display_name=subject_name,
            sensitivity=SubjectSensitivity.GENERAL_ADULT
        )

    def check_synthetic_media_policy(
        self,
        use_case: AllowedUseCase,
        generation_type: GenerationType,
        subject_name: Optional[str]
    ) -> bool:
        """
        Performs the pre-check for "Allowed" vs. "Blocked" (Req 9).
        Raises DisallowedUseCaseError if a policy is violated.
        """
        
        # A subject is required for reenactment or voice cloning
        if generation_type in [GenerationType.FACE_REENACTMENT, GenerationType.VOICE_CLONE]:
            if not subject_name:
                raise DisallowedUseCaseError("Subject name is required for reenactment or voice cloning.")
            profile = self.get_subject_profile(subject_name)
        else:
            # For fully synthetic faces, we can use a generic "stock" profile
            profile = self.get_subject_profile(subject_name or "Stock Person")

        # --- Policy: Blocked Subjects (Req 9) ---
        if profile.sensitivity == SubjectSensitivity.MINOR:
            raise DisallowedUseCaseError("Generation for minors is strictly prohibited.")
        
        if profile.sensitivity == SubjectSensitivity.VULNERABLE_PERSON:
            raise DisallowedUseCaseError("Generation for known victims of crimes is strictly prohibited.")
            
        if profile.sensitivity == SubjectSensitivity.SANCTIONED_PERSON:
            raise DisallowedUseCaseError("Generation for sanctioned persons or entities is prohibited.")
        
        if profile.sensitivity == SubjectSensitivity.PUBLIC_OFFICIAL:
            if use_case not in [AllowedUseCase.FILM_ADVERTISING]:
                raise DisallowedUseCaseError(
                    f"Use case '{use_case.value}' is not permitted for public officials. "
                    "Requires high-risk review."
                )

        # --- Policy: Allowed Generation (Req 9) ---
        if profile.sensitivity == SubjectSensitivity.STOCK_PERSON:
            if generation_type != GenerationType.FULLY_SYNTHETIC_FACE:
                raise DisallowedUseCaseError("Stock person profile is only for fully synthetic faces.")
            if use_case not in [AllowedUseCase.SYNTHETIC_SPOKESPERSON, AllowedUseCase.ML_AUGMENTATION]:
                 raise DisallowedUseCaseError(f"Use case '{use_case.value}' not allowed for stock photos.")

        if profile.sensitivity == SubjectSensitivity.GENERAL_ADULT:
            if use_case not in [AllowedUseCase.MARKETING, AllowedUseCase.FILM_ADVERTISING, AllowedUseCase.ANONYMIZATION]:
                raise DisallowedUseCaseError(f"Use case '{use_case.value}' is not approved for this subject.")

        return True

    def determine_risk_level(
        self,
        use_case: AllowedUseCase,
        subject_name: Optional[str]
    ) -> RiskLevel:
        """
        Determines the approval threshold (RiskLevel) for a request (Req 9).
        """
        profile = self.get_subject_profile(subject_name)

        # --- Policy: Approval Threshold (Req 9) ---
        if profile.sensitivity in [
            SubjectSensitivity.PUBLIC_OFFICIAL,
            SubjectSensitivity.VULNERABLE_PERSON,
            SubjectSensitivity.MINOR,
        ]:
            return RiskLevel.HIGH

        if use_case in [AllowedUseCase.MARKETING, AllowedUseCase.FILM_ADVERTISING, AllowedUseCase.ANONYMIZATION]:
            return RiskLevel.MEDIUM

        if use_case in [AllowedUseCase.SYNTHETIC_SPOKESPERSON, AllowedUseCase.ML_AUGMENTATION] and \
           profile.sensitivity == SubjectSensitivity.STOCK_PERSON:
            return RiskLevel.LOW
            
        return RiskLevel.MEDIUM

# --- CLI COMMANDS (Moved from plugin) ---

policy_app = typer.Typer(
    name="policy",
    help="Check ethical guardrails and policies for media generation (Req 9)."
)
guardrails_instance = EthicalGuardrails()
console = Console()

@policy_app.command("add-subject", help="Add a new subject profile to the policy DB.")
def cli_add_subject_profile(
    name: str = typer.Option(..., "--name", help="Display name of the subject (used for lookups)."),
    sensitivity: SubjectSensitivity = typer.Option(..., "--sensitivity", help="The sensitivity category of the subject."),
    subject_id: str = typer.Option(None, "--id", help="Unique ID (e.g., 'sub-123'). [default: random UUID]"),
    notes: str = typer.Option("", "--notes", help="Optional notes for the profile.")
):
    """
    Saves a new subject profile to the database. This is how you
    register blocked or sensitive individuals.
    """
    if not subject_id:
        subject_id = f"sub-{uuid.uuid4()}"
        
    profile = SubjectProfile(
        subject_id=subject_id,
        display_name=name,
        sensitivity=sensitivity,
        notes=notes
    )
    
    try:
        save_subject_profile(profile)
        console.print(f"[bold green]Successfully saved subject profile:[/bold green]")
        console.print_json(profile.model_dump_json(indent=2))
    except Exception as e:
        console.print(f"[bold red]Error saving profile:[/bold red] {e}")
        raise typer.Exit(code=1)


@policy_app.command("check", help="Check if a generation request is allowed.")
def cli_check_policy(
    use_case: AllowedUseCase = typer.Option(..., help="The intended use case."),
    gen_type: GenerationType = typer.Option(..., help="The type of generation."),
    subject_name: str = typer.Option(None, help="Name of the subject (if applicable).")
):
    """
    Performs a pre-check against the "Allowed" vs. "Blocked" policy.
    """
    try:
        guardrails_instance.check_synthetic_media_policy(
            use_case=use_case,
            generation_type=gen_type,
            subject_name=subject_name
        )
        console.print(f"[bold green]Policy Check PASSED[/bold green]")
        console.print(f"  > Use Case: {use_case.value}")
        console.print(f"  > Subject: {subject_name or 'N/A'}")

    except DisallowedUseCaseError as e:
        console.print(f"[bold red]Policy Check FAILED[/bold red]")
        console.print(f"  > [red]Reason: {e}[/red]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")

@policy_app.command("get-risk", help="Determine the risk level for a request.")
def cli_get_risk(
    use_case: AllowedUseCase = typer.Option(..., help="The intended use case."),
    subject_name: str = typer.Option(None, help="Name of the subject (if applicable).")
):
    """
    Determines the risk level (LOW, MEDIUM, HIGH) to identify
    the required approval threshold (e.g., single vs. dual approval).
    """
    try:
        level = guardrails_instance.determine_risk_level(
            use_case=use_case,
            subject_name=subject_name
        )
        color = "green"
        if level == RiskLevel.MEDIUM:
            color = "yellow"
        elif level == RiskLevel.HIGH:
            color = "red"
        
        console.print(f"Determined Risk Level: [bold {color}]{level.value}[/bold {color}]")
        if level == RiskLevel.LOW:
            console.print("  > Approval: Single operator approval is sufficient.")
        elif level == RiskLevel.MEDIUM:
            console.print("  > Approval: [bold]Dual approval[/bold] is required.")
        elif level == RiskLevel.HIGH:
            console.print("  > Approval: [bold]Dual approval + senior review[/bold] is required.")

    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")