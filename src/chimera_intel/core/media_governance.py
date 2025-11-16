"""
Media Governance Module.

Handles approval gates, consent logging, and integrates with
the Evidence Vault's chain of custody for auditable governance.
"""

import typer
import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional
from .schemas import ChainOfCustodyEntry, ConsentRecord, MediaAssetStatus
from .utils import console
from .local_db_service import (
    save_scan_to_db,
    get_scan_from_db
)
from .evidence_vault import store_evidence

logger = logging.getLogger(__name__)

governance_app = typer.Typer(
    name="gov",
    help="Manages media governance, approvals, and consent logs."
)

# --- Consent Log Management (Req 2) ---

def log_consent_form(
    person_name: str,
    file_content: bytes,
    details: str,
    contact_info: Optional[str] = None
) -> str:
    """
    Logs a signed consent form.
    1. Stores the encrypted consent form in the Evidence Vault.
    2. Creates a separate, searchable ConsentRecord.
    
    Returns:
        The consent_id (receipt_id) for the ConsentRecord.
    """
    logger.info(f"Logging new consent form for: {person_name}")
    
    # 1. Store the encrypted file
    try:
        file_hash = hashlib.sha256(file_content).hexdigest()
        file_receipt_id = store_evidence(
            content=file_content,
            source="consent_uploader",
            target=person_name
        )
        logger.info(f"Consent form file stored in vault: {file_receipt_id}")
    except Exception as e:
        logger.error(f"Failed to store consent form in vault: {e}")
        raise
        
    # 2. Create and save the ConsentRecord
    consent_record = ConsentRecord(
        person_name=person_name,
        contact_info=contact_info,
        details=details,
        consent_form_sha256=file_hash,
        consent_form_storage_id=file_receipt_id
    )
    
    try:
        # Save the ConsentRecord as a new scan result
        save_scan_to_db(
            target=person_name,
            module="consent_log", # Special module name
            data=consent_record.model_dump(),
            scan_id=consent_record.consent_id # Use the record's own ID
        )
        logger.info(f"ConsentRecord saved to DB: {consent_record.consent_id}")
        return consent_record.consent_id
        
    except Exception as e:
        logger.error(f"Failed to save ConsentRecord to DB: {e}")
        raise

def get_consent_record(consent_id: str) -> Optional[ConsentRecord]:
    """Retrieves a consent record from the database."""
    try:
        record_data = get_scan_from_db(consent_id, module_name="consent_log")
        if not record_data:
            return None
        return ConsentRecord(**record_data['data'])
    except Exception as e:
        logger.error(f"Failed to retrieve consent record {consent_id}: {e}")
        return None

# --- Approval Gates (Req 1) ---

def _get_data_receipt(receipt_id: str) -> Optional[dict]:
    """Helper to retrieve a data_custodian receipt."""
    try:
        receipt_data = get_scan_from_db(receipt_id, module_name="data_custodian")
        if not receipt_data:
            logger.warning(f"No data custodian receipt found for ID: {receipt_id}")
            return None
        return receipt_data
    except Exception as e:
        logger.error(f"Error fetching receipt {receipt_id}: {e}")
        return None

def _update_chain_of_custody(
    receipt_data: dict,
    action: str,
    actor: str,
    details: str
) -> bool:
    """
    Adds a new entry to the receipt's chain of custody and saves it.
    """
    try:
        new_entry = ChainOfCustodyEntry(
            action=action,
            actor=actor,
            details=details,
            timestamp=datetime.now(timezone.utc).isoformat()
        ).model_dump()
        
        receipt_data['data']['chain_of_custody'].append(new_entry)
        
        # Save the updated receipt back to the DB
        save_scan_to_db(
            target=receipt_data['target'],
            module="data_custodian",
            data=receipt_data['data'],
            scan_id=receipt_data['scan_id']
        )
        return True
    except Exception as e:
        logger.error(f"Failed to update chain of custody for {receipt_data['scan_id']}: {e}")
        return False

def request_media_approval(receipt_id: str, requestor: str, reason: str):
    """
    Flags a media asset as 'PENDING_REVIEW' in its audit log.
    """
    receipt_data = _get_data_receipt(receipt_id)
    if not receipt_data:
        raise ValueError(f"No receipt found for ID: {receipt_id}")
        
    success = _update_chain_of_custody(
        receipt_data=receipt_data,
        action=MediaAssetStatus.PENDING_REVIEW.value,
        actor=requestor,
        details=reason
    )
    if not success:
        raise Exception("Failed to save approval request to audit log.")
    logger.info(f"Approval requested for {receipt_id} by {requestor}")

def set_media_approval_status(
    receipt_id: str,
    approver: str,
    status: MediaAssetStatus,
    notes: str
):
    """
    Sets the final approval status (APPROVED or REJECTED) in the
    media asset's audit log.
    """
    receipt_data = _get_data_receipt(receipt_id)
    if not receipt_data:
        raise ValueError(f"No receipt found for ID: {receipt_id}")

    if status not in [MediaAssetStatus.APPROVED, MediaAssetStatus.REJECTED]:
        raise ValueError("Status must be APPROVED or REJECTED.")
        
    success = _update_chain_of_custody(
        receipt_data=receipt_data,
        action=status.value,
        actor=approver,
        details=notes
    )
    if not success:
        raise Exception(f"Failed to set status '{status.value}' to audit log.")
    logger.info(f"Status for {receipt_id} set to {status.value} by {approver}")

# --- CLI COMMANDS ---

@governance_app.command("log-consent", help="Logs a new consent form.")
def cli_log_consent(
    person_name: str = typer.Option(..., "--name", help="Full name of the person giving consent."),
    form_path: typer.FileBinaryRead = typer.Option(..., "--form", help="Path to the signed consent form (PDF, PNG, etc.)."),
    details: str = typer.Option(..., "--details", help="Details of what the consent covers, e.g., 'Use for Project X'."),
    contact: Optional[str] = typer.Option(None, "--contact", help="Optional contact info (email/phone)."),
):
    """
    Encrypts and stores a consent form, creating an auditable
    ConsentRecord. Returns a consent_id to be used in media manifests.
    """
    with console.status("[bold cyan]Logging consent form...[/bold cyan]"):
        try:
            content = form_path.read()
            if not content:
                console.print("[bold red]Error:[/bold red] File is empty.")
                raise typer.Exit(code=1)
                
            consent_id = log_consent_form(
                person_name=person_name,
                file_content=content,
                details=details,
                contact_info=contact
            )
            console.print(f"[green]Consent form successfully logged.[/green]")
            console.print(f"  > Person: {person_name}")
            console.print(f"  > Consent ID: [bold yellow]{consent_id}[/bold yellow]")
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(code=1)

@governance_app.command("request-approval", help="Request review for a media asset.")
def cli_request_approval(
    receipt_id: str = typer.Argument(..., help="The receipt_id of the media manifest to review."),
    requestor: str = typer.Option(..., "--by", help="The user/email of the person requesting review."),
    reason: str = typer.Option("Please review for publication.", "--reason", help="Reason for the review request.")
):
    """
    Adds a 'PENDING_REVIEW' entry to the asset's chain of custody.
    """
    with console.status(f"[bold cyan]Submitting {receipt_id} for review...[/bold cyan]"):
        try:
            request_media_approval(receipt_id, requestor, reason)
            console.print(f"[green]Successfully requested approval for {receipt_id}.[/green]")
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(code=1)

@governance_app.command("approve", help="Approve a media asset for publication.")
def cli_approve_media(
    receipt_id: str = typer.Argument(..., help="The receipt_id of the media manifest."),
    approver: str = typer.Option(..., "--by", help="The user/email of the approver."),
    notes: str = typer.Option("Approved for external release.", "--notes", help="Approval notes for the audit log.")
):
    """
    Adds an 'APPROVED' entry to the asset's chain of custody.
    """
    with console.status(f"[bold cyan]Approving {receipt_id}...[/bold cyan]"):
        try:
            set_media_approval_status(
                receipt_id=receipt_id,
                approver=approver,
                status=MediaAssetStatus.APPROVED,
                notes=notes
            )
            console.print(f"[bold green]Asset {receipt_id} has been APPROVED.[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(code=1)

@governance_app.command("reject", help="Reject a media asset.")
def cli_reject_media(
    receipt_id: str = typer.Argument(..., help="The receipt_id of the media manifest."),
    rejector: str = typer.Option(..., "--by", help="The user/email of the person rejecting."),
    reason: str = typer.Option(..., "--reason", help="Rejection reason for the audit log.")
):
    """
    Adds a 'REJECTED' entry to the asset's chain of custody.
    """
    with console.status(f"[bold yellow]Rejecting {receipt_id}...[/bold yellow]"):
        try:
            set_media_approval_status(
                receipt_id=receipt_id,
                approver=rejector,
                status=MediaAssetStatus.REJECTED,
                notes=reason
            )
            console.print(f"[bold red]Asset {receipt_id} has been REJECTED.[/bold red]")
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(code=1)