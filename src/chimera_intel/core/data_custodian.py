"""
Module for Data Custodian (GRC).

Handles auditable integrity, cryptographic timestamping, chain-of-custody,
and judicial-hold management for all intelligence data.

MODIFIED: This version now uses the local_db_service (SQLite)
instead of the production 'database.py' to align with evidence_vault.py
and support updating records.
"""

import typer
import logging
import hashlib
import json  
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from chimera_intel.core.schemas import ChainOfCustodyEntry, AuditableDataReceipt
from .utils import save_or_print_results, console
from .local_db_service import ( 
    save_scan_to_db, 
    get_scan_from_db
)
from .project_manager import resolve_target

logger = logging.getLogger(__name__)
data_custodian_app = typer.Typer()

def create_data_receipt(
    content: bytes, source: str, target: str
) -> AuditableDataReceipt:
    """
    Creates a cryptographically timestamped receipt for a piece of raw data.
    """
    logger.info(f"Creating data receipt for source: {source}")
    
    now_utc = datetime.now(timezone.utc)
    content_hash = hashlib.sha256(content).hexdigest()
    # Use the content hash + timestamp to create a unique, deterministic-but-unguessable ID
    receipt_id = f"R-{hashlib.md5(f'{content_hash}{now_utc.isoformat()}'.encode()).hexdigest()}"
    
    entry = ChainOfCustodyEntry(
        action="INGEST", 
        details=f"Data ingested from source: {source}"
    )
    
    receipt = AuditableDataReceipt(
        receipt_id=receipt_id,
        target=target,
        source=source,
        content_sha256=content_hash,
        ingest_timestamp=now_utc.isoformat(),
        chain_of_custody=[entry]
    )
    
    # In a real system, this receipt is saved to a dedicated, immutable DB ledger
    # For this example, we save it to the general project DB (local_db_service).
    try:
        save_scan_to_db(
            target=target, 
            module="data_custodian", 
            data=receipt.model_dump(), 
            scan_id=receipt_id  # Use the receipt_id as the scan_id
        )
    except Exception as e:
        logger.error(f"Failed to save receipt to DB: {e}")
        # Continue anyway for demo, but log error
    
    return receipt


def set_judicial_hold(
    receipt_id: str, hold: bool, reason: str, target: str
) -> Dict[str, Any]:
    """
    (REAL) Applies or releases a judicial hold on a data receipt.
    """
    logger.info(f"Setting judicial hold for {receipt_id} to {hold}")
    
    # --- (REAL IMPLEMENTATION) ---
    # 1. Fetch the existing receipt
    try:
        receipt_record = get_scan_from_db(receipt_id, module_name="data_custodian")
        if not receipt_record:
            raise ValueError(f"Receipt ID {receipt_id} not found in 'data_custodian' module.")
        
        # 2. Parse the data
        receipt_data = receipt_record.get("data", {})
        if not isinstance(receipt_data, dict):
             receipt_data = json.loads(receipt_data) # Parse from string if needed
             
        receipt = AuditableDataReceipt.model_validate(receipt_data)

    except Exception as e:
        logger.error(f"Failed to fetch or parse receipt {receipt_id}: {e}")
        return {"status": "error", "message": str(e)}

    # 3. Update the receipt
    action = "JUDICIAL_HOLD_APPLIED" if hold else "JUDICIAL_HOLD_RELEASED"
    receipt.judicial_hold = hold
    receipt.judicial_hold_reason = reason if hold else None
    receipt.chain_of_custody.append(
        ChainOfCustodyEntry(action=action, details=reason)
    )
    
    # 4. Save the updated receipt back to the DB, overwriting the old one
    try:
        save_scan_to_db(
            target=receipt.target,
            module="data_custodian",
            data=receipt.model_dump(),
            scan_id=receipt_id  # This ensures we UPDATE the existing record
        )
    except Exception as e:
        logger.error(f"Failed to save updated receipt {receipt_id}: {e}")
        return {"status": "error", "message": f"Failed to save update: {e}"}
    
    # --- (END REAL IMPLEMENTATION) ---
    
    return {
        "receipt_id": receipt_id,
        "status": f"Judicial hold set to {hold}",
        "reason": reason,
        "updated_timestamp": datetime.now(timezone.utc).isoformat()
    }


@data_custodian_app.command("timestamp")
def run_timestamp_cli(
    target: Optional[str] = typer.Argument(
        None, help="The target/project to associate this data with."
    ),
    content: str = typer.Option(
        ..., "--content", help="The raw text content to timestamp."
    ),
    source: str = typer.Option(
        ..., "--source", help="The source URL or identifier for this data."
    ),
):
    """
    Cryptographically timestamps raw data and creates an auditable receipt.
    """
    target_name = resolve_target(target, required_assets=[])
    
    with console.status(
        f"[bold cyan]Creating auditable receipt for {source}...[/bold cyan]"
    ):
        receipt_model = create_data_receipt(
            content=content.encode('utf-8'),
            source=source,
            target=target_name
        )
    
    console.print(f"[green]Receipt created:[/green] {receipt_model.receipt_id}")
    save_or_print_results(receipt_model.model_dump(), None)


@data_custodian_app.command("hold")
def run_judicial_hold_cli(
    receipt_id: str = typer.Argument(..., help="The receipt_id to place on hold."),
    reason: str = typer.Option(
        ..., "--reason", help="The reason for the hold (e.g., 'Legal Case #123')."
    ),
    release: bool = typer.Option(
        False, "--release", help="Set this flag to release the hold."
    ),
    target: Optional[str] = typer.Option(
        "default", help="The project target."
    ),
):
    """
    Applies or releases a judicial hold on a piece of data.
    """
    hold = not release
    with console.status(
        f"[bold yellow]Setting judicial hold for {receipt_id} to {hold}...[/bold yellow]"
    ):
        # Target is a fallback, but not really used in the real logic
        result = set_judicial_hold(receipt_id, hold, reason, target)
    
    save_or_print_results(result, None)