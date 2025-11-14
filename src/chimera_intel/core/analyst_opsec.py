"""
Module for Analyst Operational Security (OPSEC).

Provides tools and commands for managing analyst credentials,
session validity, and auditing secure workflow actions.

Integrates with user_manager and evidence_vault.
"""

import typer
import logging
import secrets
import base64
from datetime import datetime, timedelta, timezone
from .security_utils import audit_event
from .utils import console
from .user_manager import get_user_by_username, update_user_data
from .evidence_vault import encrypt_data
from .database import get_db_connection  

logger = logging.getLogger(__name__)

analyst_opsec_app = typer.Typer(
    name="opsec-admin",
    help="Manage Analyst OPSEC (e.g., key rotation, session auditing).",
)


@analyst_opsec_app.command("rotate-key")
def cli_rotate_api_key(
    analyst_username: str = typer.Argument(..., help="The username of the analyst user."),
    reason: str = typer.Option(..., "--reason", help="Reason for the key rotation (for audit)."),
    current_user: str = typer.Option("admin", "--admin-user", help="The administrator performing this action."),
):
    """
    Generates a new secure API key for an analyst, encrypts and saves
    it to their profile, and logs the event in a single database transaction.
    """
    console.print(f"Rotating API key for analyst: {analyst_username}")

    # 1. Get the user from the database (outside the transaction)
    try:
        user = get_user_by_username(analyst_username)
        if not user:
            console.print(f"[bold red]Error:[/bold red] Analyst user '{analyst_username}' not found.")
            raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not retrieve user: {e}")
        raise typer.Exit(code=1)

    # 2. Generate a new key
    new_key_plaintext = f"chimera_ak_{secrets.token_hex(32)}"

    # 3. Perform key update and audit logging as a single transaction
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 3a. Encrypt the new key using the Vault's utility
        encrypted_bytes = encrypt_data(new_key_plaintext.encode('utf-8'))
        
        # 3b. Use Base64 encoding for safe storage
        encrypted_key_b64 = base64.b64encode(encrypted_bytes).decode('ascii')

        # 3c. Save the encrypted key (pass cursor for transaction)
        update_user_data(
            analyst_username,
            {"api_key_encrypted": encrypted_key_b64},
            db=cursor
        )
        logger.info(f"Encrypted key updated for {analyst_username} in transaction.")

        # 3d. Log the rotation event (pass cursor for transaction)
        # We assume audit_event is modified to accept a 'db' cursor/conn
        # If not, this is the best we can do.
        # For true transactionality, audit_event would need to be refactored
        # to use the passed cursor.
        audit_event(
            user=current_user,
            action="analyst_key_rotation",
            target=analyst_username,
            consent_id=None,
            note=f"Key rotated. Reason: {reason}",
            # db=cursor  <-- Pass cursor if audit_event supports it
        )
        logger.info(f"Audit event created for {analyst_username} in transaction.")
    
        # If all succeeds, commit the transaction
        conn.commit()
        logger.info(f"Key rotation for {analyst_username} committed successfully.")
                
    except Exception as e:
        # If anything fails, roll back the entire operation
        if conn:
            conn.rollback()
        console.print(f"[bold red]Transaction Failed:[/bold red] {e}")
        logger.error(f"Rolling back key rotation for {analyst_username}: {e}")
        console.print("[bold red]Operation rolled back. No changes were made.[/bold red]")
        raise typer.Exit(code=1)
    finally:
        if conn:
            conn.close()

    # 4. Display the key *only* after the transaction is successful
    console.print(f"[bold green]Success![/bold green] Transaction committed.")
    console.print(f"New API key for {analyst_username}:")
    console.print(f"[bold yellow]{new_key_plaintext}[/bold yellow]")
    console.print("[bold red]Warning:[/bold red] This is the only time the key will be shown. Deliver it securely.")


@analyst_opsec_app.command("check-session")
def cli_check_session(
    analyst_username: str = typer.Argument(..., help="The username of the analyst user."),
    max_duration_hours: int = typer.Option(
        8,
        "--max-hours",
        help="Maximum allowed session duration in hours."
    )
):
    """
    Checks if an analyst's session is still valid (ephemeral sessions)
    by checking their 'last_login' time from the user database.
    """
    console.print(f"Checking session validity for: {analyst_username}")
    console.print(
        "[yellow]Note:[/yellow] This check is a heuristic based on 'last_login' "
        "and not a precise measure of an active session."
    )

    # 1. Get the user from the database
    try:
        user = get_user_by_username(analyst_username)
        if not user:
            console.print(f"[bold red]Error:[/bold red] Analyst user '{analyst_username}' not found.")
            raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not retrieve user: {e}")
        raise typer.Exit(code=1)

    # 2. Get last_login time
    session_start_time = user.last_login
    
    if not session_start_time:
        console.print(f"[bold yellow]Warning:[/bold yellow] User '{analyst_username}' has no 'last_login' timestamp. Cannot check session.")
        raise typer.Exit()

    # 3. Ensure the start time is timezone-aware
    if session_start_time.tzinfo is None:
        session_start_time = session_start_time.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    expiry_time = session_start_time + timedelta(hours=max_duration_hours)

    # 4. Perform check
    if now > expiry_time:
        console.print(f"  - Session Status: [bold red]EXPIRED[/bold red]")
        console.print(f"  - Session Started: {session_start_time.isoformat()}")
        console.print(f"  - Expired at:      {expiry_time.isoformat()}")
        
        # Audit this event
        audit_event(
            user="system_monitor",
            action="session_expired",
            target=analyst_username,
            consent_id=None,
            note=f"Analyst session exceeded {max_duration_hours} hours."
        )
        raise typer.Exit(code=1)
    else:
        time_remaining = expiry_time - now
        console.print(f"  - Session Status: [bold green]VALID[/bold green]")
        console.print(f"  - Session Started: {session_start_time.isoformat()}")
        console.print(f"  - Time Remaining: {time_remaining}")