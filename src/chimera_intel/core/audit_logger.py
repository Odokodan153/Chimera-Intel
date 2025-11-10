"""
Module for an Immutable Audit Log using a chained-hash structure.
This provides a secure log for provenance (F3).
"""

import typer
import json
import logging
import hashlib
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any, Iterator
import os
import uuid
from .utils import console

logger = logging.getLogger(__name__)

# Simple file-based "database" for the audit log
AUDIT_LOG_PATH = "audit_log.jsonl"
GENESIS_HASH = "0" * 64  # The hash for the first entry's "previous_hash"

class AuditLogEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user: str
    action_name: str
    target: Optional[str] = None
    status: str  # e.g., "SUCCESS", "FAILURE", "PENDING_REVIEW"
    details: Dict[str, Any] = Field(default_factory=dict)
    previous_hash: str
    entry_hash: Optional[str] = None

    def _data_to_hash(self) -> str:
        """Creates the canonical string representation for hashing, excluding the hash itself."""
        data = self.model_dump(exclude={'entry_hash'}, mode="json")
        # Ensure consistent ordering for hashing
        return json.dumps(data, sort_keys=True)

    def calculate_hash(self) -> str:
        """Calculates the SHA-256 hash of the entry."""
        data_string = self._data_to_hash()
        return hashlib.sha256(data_string.encode()).hexdigest()

class AuditLogger:
    """Manages the creation and verification of the immutable audit log."""

    def __init__(self, log_path: str = AUDIT_LOG_PATH):
        self.log_path = log_path
        self._initialize_log()

    def _initialize_log(self):
        """Ensures the log file exists."""
        if not os.path.exists(self.log_path):
            logger.info("Initializing new audit log at %s", self.log_path)
            # This is not strictly necessary for append-only, but good practice.
            open(self.log_path, 'a').close()

    def _get_last_hash(self) -> str:
        """Finds the hash of the very last entry in the log."""
        last_hash = GENESIS_HASH
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                last_line = None
                for line in f:
                    if line.strip():
                        last_line = line
                
                if last_line:
                    last_entry_data = json.loads(last_line)
                    last_hash = last_entry_data.get("entry_hash", GENESIS_HASH)
        except (FileNotFoundError, json.JSONDecodeError):
            return GENESIS_HASH
        except Exception as e:
            logger.error("Error reading last hash from %s: %s. Using genesis hash.", self.log_path, e)
            return GENESIS_HASH
        return last_hash

    def log_action(
        self,
        user: str,
        action_name: str,
        status: str,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLogEntry:
        """
        Creates, hashes, and appends a new entry to the audit log.
        """
        last_hash = self._get_last_hash()
        
        entry = AuditLogEntry(
            user=user,
            action_name=action_name,
            status=status,
            target=target,
            details=details or {},
            previous_hash=last_hash
        )
        
        # Calculate and set the entry's own hash
        entry.entry_hash = entry.calculate_hash()
        
        # Append the new entry
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(entry.model_dump_json() + "\n")
            logger.info("Logged audit entry %s for user %s, action %s", entry.id, user, action_name)
            return entry
        except Exception as e:
            logger.error("CRITICAL: Failed to write to audit log! %s", e)
            # In a real system, this might halt the action
            raise

    def _iter_entries(self) -> Iterator[AuditLogEntry]:
        """Iterates through all entries in the log file."""
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        yield AuditLogEntry(**json.loads(line))
        except FileNotFoundError:
            return
        except Exception as e:
            logger.error("Failed to read audit log during iteration: %s", e)
            raise

    def verify_chain(self) -> bool:
        """
        Verifies the integrity of the entire audit log chain.
        Returns True if valid, False if a break is detected.
        """
        logger.info("Starting audit log chain verification...")
        expected_prev_hash = GENESIS_HASH
        
        try:
            for i, entry in enumerate(self._iter_entries()):
                # 1. Verify the entry's own hash
                recalculated_hash = entry.calculate_hash()
                if recalculated_hash != entry.entry_hash:
                    logger.error("Chain tampered! Entry %s (ID: %s) hash mismatch.", i, entry.id)
                    console.print(f"[bold red]TAMPERING DETECTED![/bold red] Entry {i} (ID: {entry.id}) has been modified.")
                    return False
                
                # 2. Verify the link to the previous entry
                if entry.previous_hash != expected_prev_hash:
                    logger.error("Chain tampered! Entry %s (ID: %s) previous_hash does not match.", i, entry.id)
                    console.print(f"[bold red]TAMPERING DETECTED![/bold red] Chain broken at entry {i} (ID: {entry.id}).")
                    return False
                
                # 3. Set expectation for the next loop
                expected_prev_hash = entry.entry_hash
            
            logger.info("Audit log verification successful. Chain is intact.")
            return True
        except Exception as e:
            logger.error("Verification failed due to read error: %s", e)
            console.print(f"[bold red]Error:[/bold red] Failed to read audit log for verification: {e}")
            return False

# --- Typer CLI Application ---

audit_app = typer.Typer(name="audit", help="Manage and verify the immutable audit log.")
audit_logger_instance = AuditLogger()

@audit_app.command("log")
def cli_log_action(
    user: str = typer.Option("cli_user", "--user", help="User performing the action."),
    action: str = typer.Option("test:action", "--action", help="Action name."),
    status: str = typer.Option("SUCCESS", "--status", help="Action status.")
):
    """(Test command) Logs a sample action to the audit trail."""
    try:
        entry = audit_logger_instance.log_action(user, action, status, target="test_target")
        console.print(f"[green]Logged new audit entry:[/green] {entry.id}")
    except Exception as e:
        console.print(f"[bold red]Error logging action:[/bold red] {e}")
        raise typer.Exit(code=1)

@audit_app.command("verify")
def cli_verify_chain():
    """Verifies the integrity of the entire audit log hash chain."""
    console.print(f"Verifying audit log at: {audit_logger_instance.log_path}")
    if audit_logger_instance.verify_chain():
        console.print("[bold green]SUCCESS:[/bold green] Audit log chain is intact and valid.")
    else:
        console.print("[bold red]FAILURE:[/bold red] Audit log chain is broken or has been tampered with!")
        raise typer.Exit(code=1)