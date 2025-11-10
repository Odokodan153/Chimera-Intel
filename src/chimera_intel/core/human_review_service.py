"""
Module for managing a human review queue for sensitive actions.
This provides a queue for F1 (Human Review) and complements action_governance.py.
"""

import typer
import json
import logging
from .schemas import ReviewRequest, ReviewStatus
from datetime import datetime
from typing import List, Optional, Dict, Any
from .utils import console

logger = logging.getLogger(__name__)

# Simple file-based "database" for the review queue
REVIEW_QUEUE_PATH = "review_queue.json"



class HumanReviewService:
    """Manages the queue of actions pending human review."""

    def __init__(self, db_path: str = REVIEW_QUEUE_PATH):
        self.db_path = db_path

    def _load_queue(self) -> List[ReviewRequest]:
        """Loads the full review queue from the file."""
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return [ReviewRequest(**item) for item in data]
        except (FileNotFoundError, json.JSONDecodeError):
            return []
        except Exception as e:
            logger.error("Failed to load review queue: %s", e)
            return []

    def _save_queue(self, queue: List[ReviewRequest]) -> None:
        """Saves the full review queue to the file."""
        try:
            with open(self.db_path, "w", encoding="utf-8") as f:
                data = [item.model_dump(mode="json") for item in queue]
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error("Failed to save review queue: %s", e)

    def submit_for_review(
        self,
        user: str,
        action_name: str,
        target: str,
        provenance: Optional[Dict[str, Any]] = None,
        justification: Optional[str] = None
    ) -> ReviewRequest:
        """
        Submits a new action to the queue for human review.
        This would be called by action_governance.py instead of just failing.
        """
        request = ReviewRequest(
            user=user,
            action_name=action_name,
            target=target,
            provenance=provenance or {},
            justification=justification
        )
        
        queue = self._load_queue()
        queue.append(request)
        self._save_queue(queue)
        
        logger.warning("Action '%s' on target '%s' by user '%s' requires human review. Request ID: %s",
                       action_name, target, user, request.id)
        console.print(f"[bold yellow]ACTION PENDING:[/bold yellow] Action '{action_name}' requires human review. Request ID: {request.id}")
        return request

    def get_reviews(self, status: ReviewStatus = ReviewStatus.PENDING) -> List[ReviewRequest]:
        """Gets all review requests, filtered by status."""
        queue = self._load_queue()
        return [req for req in queue if req.status == status]

    def _update_review_status(self, request_id: str, new_status: ReviewStatus, reviewer: str) -> Optional[ReviewRequest]:
        """Helper to find and update a review request."""
        queue = self._load_queue()
        updated_request = None
        for request in queue:
            if request.id == request_id:
                if request.status != ReviewStatus.PENDING:
                    logger.warning("Review request %s is already in status %s.", request_id, request.status)
                    return None
                request.status = new_status
                request.reviewer = reviewer
                request.reviewed_at = datetime.utcnow()
                updated_request = request
                break
        
        if updated_request:
            self._save_queue(queue)
            logger.info("Review request %s set to %s by %s.", request_id, new_status, reviewer)
            return updated_request
        else:
            logger.error("Could not find pending review request with ID: %s", request_id)
            return None

    def approve_request(self, request_id: str, reviewer: str) -> Optional[ReviewRequest]:
        """Approves a pending review request."""
        return self._update_review_status(request_id, ReviewStatus.APPROVED, reviewer)

    def deny_request(self, request_id: str, reviewer: str) -> Optional[ReviewRequest]:
        """Denies a pending review request."""
        return self._update_review_status(request_id, ReviewStatus.DENIED, reviewer)


# --- Typer CLI Application ---

review_app = typer.Typer(name="review", help="Manage the human review queue for sensitive actions.")
review_service_instance = HumanReviewService()

@review_app.command("list")
def list_pending_reviews():
    """Lists all actions currently pending human review."""
    pending = review_service_instance.get_reviews(status=ReviewStatus.PENDING)
    if not pending:
        console.print("[dim]No actions are pending review.[/dim]")
        return
    
    console.print(f"[bold]Pending Review Queue ({len(pending)} items):[/bold]")
    for req in pending:
        console.print(f"- [bold]ID:[/bold] {req.id}")
        console.print(f"  [bold]Action:[/bold] {req.action_name}")
        console.print(f"  [bold]Target:[/bold] {req.target}")
        console.print(f"  [bold]User:[/bold] {req.user}")
        console.print(f"  [bold]Time:[/bold] {req.timestamp.isoformat()}")

@review_app.command("approve")
def approve_action(
    request_id: str = typer.Argument(..., help="The ID of the review request to approve."),
    reviewer: str = typer.Option("analyst", "--user", "-u", help="The user/reviewer approving the action.")
):
    """Approves a sensitive action."""
    request = review_service_instance.approve_request(request_id, reviewer)
    if request:
        console.print(f"[bold green]APPROVED:[/bold green] Action '{request.action_name}' on '{request.target}' (ID: {request.id}).")
    else:
        console.print(f"[bold red]Error:[/bold red] Could not find pending request with ID: {request_id}")
        raise typer.Exit(code=1)

@review_app.command("deny")
def deny_action(
    request_id: str = typer.Argument(..., help="The ID of the review request to deny."),
    reviewer: str = typer.Option("analyst", "--user", "-u", help="The user/reviewer denying the action.")
):
    """Denies a sensitive action."""
    request = review_service_instance.deny_request(request_id, reviewer)
    if request:
        console.print(f"[bold red]DENIED:[/bold red] Action '{request.action_name}' on '{request.target}' (ID: {request.id}).")
    else:
        console.print(f"[bold red]Error:[/bold red] Could not find pending request with ID: {request_id}")
        raise typer.Exit(code=1)