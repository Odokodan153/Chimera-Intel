"""
Encrypted Evidence Vault Module.

Handles the secure, encrypted storage and retrieval of sensitive
intelligence data, integrating with the Data Custodian for provenance.

MODIFIED: This version now uses the local_db_service (SQLite)
instead of the production 'database.py'.
"""

import typer
import logging
import os
from cryptography.fernet import Fernet, InvalidToken
from .schemas import ChainOfCustodyEntry
from .utils import console
from .local_db_service import ( 
    save_scan_to_db, 
    get_scan_from_db
)

from .data_custodian import create_data_receipt
from .config_loader import CONFIG
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# This app will be merged with the data_custodian_app
vault_app = typer.Typer(
    name="grc", # Use the same name to merge commands
    help="Manages Data Custodian (GRC) and the Encrypted Evidence Vault."
)

def _get_vault_key() -> Fernet:
    """Retrieves the Fernet encryption key from env variables."""
    key = os.environ.get("EVIDENCE_VAULT_KEY")
    if not key:
        logger.error("EVIDENCE_VAULT_KEY is not set in .env file.")
        raise ValueError("Encryption key not found.")
    
    # In a real system, you'd validate the key format
    return Fernet(key.encode())

def encrypt_data(content: bytes) -> bytes:
    """Encrypts raw data using the vault key."""
    f = _get_vault_key()
    return f.encrypt(content)

def decrypt_data(token: bytes) -> bytes:
    """Decrypts an encrypted token using the vault key."""
    f = _get_vault_key()
    try:
        return f.decrypt(token)
    except InvalidToken:
        logger.error("Failed to decrypt evidence: Invalid token.")
        raise ValueError("Decryption failed. Data may be corrupt or key is wrong.")


def store_evidence(
    content: bytes, source: str, target: str
) -> str:
    """
    Encrypts sensitive data and stores it, creating a data receipt.
    
    1. Creates a provenance receipt (hash of original content).
    2. Encrypts the original content.
    3. Saves the encrypted content to the 'evidence_vault' store.
    
    Returns:
        The receipt_id (vault_id) for the stored evidence.
    """
    logger.info(f"Storing new evidence for target {target} from {source}")
    
    # 1. Create the auditable receipt (hashes original content)
    receipt = create_data_receipt(content, source, target)
    
    # 2. Encrypt the original content
    try:
        encrypted_content = encrypt_data(content)
    except Exception as e:
        logger.error(f"Failed to encrypt data for {receipt.receipt_id}: {e}")
        # We have a receipt, but no data. This is a problem.
        # In a real system, this would be a transactional rollback.
        raise
        
    # 3. Save the encrypted content to the DB
    # We re-use save_scan_to_db to store the encrypted blob.
    # The 'module' name 'evidence_vault' distinguishes it.
    try:
        save_scan_to_db(
            target=target,
            module="evidence_vault", # Special module name for encrypted data
            data={"encrypted_blob": encrypted_content.decode('latin-1')}, # Store as string
            scan_id=receipt.receipt_id # Use same ID as receipt
        )
    except Exception as e:
        logger.error(f"Failed to save encrypted blob to DB: {e}")
        raise

    logger.info(f"Successfully stored and encrypted evidence: {receipt.receipt_id}")
    return receipt.receipt_id

def retrieve_evidence(receipt_id: str, reason: str) -> bytes:
    """
    Retrieves and decrypts sensitive data, logging the access event.
    """
    logger.info(f"Retrieving evidence {receipt_id} for reason: {reason}")
    
    # 1. Log the access event to the chain of custody
    # We fetch the *receipt* first to log the access
    try:
        receipt_data = get_scan_from_db(receipt_id)
        if not receipt_data or receipt_data.get("module") != "data_custodian":
            # Try to fetch from the specific module if not found (fallback)
            receipt_data = get_scan_from_db(receipt_id, module_name="data_custodian")
            if not receipt_data:
                raise ValueError(f"No data custodian receipt found for ID: {receipt_id}")

        # Add the access entry
        receipt_data['data']['chain_of_custody'].append(
            ChainOfCustodyEntry(
                action="ACCESS", 
                details=reason,
                timestamp=datetime.now(timezone.utc).isoformat()
            ).model_dump()
        )
        # Save the updated receipt
        save_scan_to_db(
            target=receipt_data['target'],
            module="data_custodian",
            data=receipt_data['data'],
            scan_id=receipt_id
        )
    except Exception as e:
        logger.error(f"Failed to log access event for {receipt_id}: {e}")
        # Continue to retrieval, but this is a high-priority alert.
        
    # 2. Retrieve and decrypt the evidence blob
    try:
        vault_entry = get_scan_from_db(receipt_id, module_name="evidence_vault")
        if not vault_entry:
            raise ValueError(f"No evidence vault blob found for ID: {receipt_id}")
        
        encrypted_blob = vault_entry['data']['encrypted_blob'].encode('latin-1')
        decrypted_content = decrypt_data(encrypted_blob)
        
        logger.info(f"Successfully decrypted and retrieved {receipt_id}")
        return decrypted_content

    except Exception as e:
        logger.error(f"Failed to retrieve or decrypt evidence {receipt_id}: {e}")
        raise

# --- CLI COMMANDS ---
# (Rest of the file is unchanged from)

@vault_app.command("store")
def run_store_evidence(
    target: str = typer.Option(..., "--target", help="The target/project to associate."),
    content: str = typer.Option(..., "--content", help="The raw text content to store."),
    source: str = typer.Option(..., "--source", help="The source URL or identifier."),
):
    """
    (NEW) Encrypts and stores sensitive data in the evidence vault.
    
    This creates both a data receipt (for provenance) and an
    encrypted vault entry (for confidentiality).
    """
    with console.status("[bold cyan]Storing and encrypting evidence...[/bold cyan]"):
        try:
            receipt_id = store_evidence(
                content=content.encode('utf-8'),
                source=source,
                target=target
            )
            console.print(f"[green]Evidence securely stored.[/green] Receipt ID: {receipt_id}")
        except Exception as e:
            console.print(f"[bold red]Error storing evidence:[/bold red] {e}")

@vault_app.command("retrieve")
def run_retrieve_evidence(
    receipt_id: str = typer.Argument(..., help="The receipt_id (vault_id) to retrieve."),
    reason: str = typer.Option(..., "--reason", help="The reason for data access (for audit log)."),
):
    """
    (NEW) Retrieves and decrypts sensitive data from the evidence vault.
    
    This action is logged to the item's chain of custody.
    """
    with console.status(f"[bold yellow]Retrieving {receipt_id}...[/bold yellow]"):
        try:
            content = retrieve_evidence(receipt_id, reason)
            console.print(f"[green]Access logged. Decrypted Content:[/green]")
            # Print content directly, don't save it
            console.print(content.decode('utf-8'))
        except Exception as e:
            console.print(f"[bold red]Error retrieving evidence:[/bold red] {e}")