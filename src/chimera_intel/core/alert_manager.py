"""
Module for dispatching alerts with provenance, confidence, and legal flagging.
"""

import typer
import json
import logging
from enum import Enum
from datetime import datetime
from typing import List, Optional, Dict, Any
import uuid
from .utils import console
from .schemas import Alert,AlertLevel,AlertStatus 
from .config_loader import CONFIG
import httpx

logger = logging.getLogger(__name__)

# Simple file-based "database" for alerts
ALERT_DB_PATH = "alerts.jsonl"



class AlertManager:
    """Handles the creation and dispatching of alerts."""

    def __init__(self, db_path: str = ALERT_DB_PATH):
        self.db_path = db_path
        self.webhook_url = CONFIG.reporting.alert_webhook_url

    def _save_alert(self, alert: Alert) -> None:
        """Appends an alert to the JSONL database."""
        try:
            with open(self.db_path, "a", encoding="utf-8") as f:
                f.write(alert.model_dump_json() + "\n")
        except Exception as e:
            logger.error("Failed to save alert to %s: %s", self.db_path, e)

    def _dispatch_to_webhook(self, alert: Alert) -> None:
        """Sends the alert to a configured webhook URL."""
        if not self.webhook_url:
            return  # No webhook configured
        
        try:
            with httpx.Client() as client:
                response = client.post(self.webhook_url, json=alert.model_dump(mode="json"))
                if 200 <= response.status_code < 300:
                    logger.info("Successfully dispatched alert %s to webhook.", alert.id)
                else:
                    logger.warning("Failed to dispatch alert %s to webhook. Status: %s", alert.id, response.status_code)
        except Exception as e:
            logger.error("Error sending alert to webhook %s: %s", self.webhook_url, e)

    def dispatch_alert(
        self,
        title: str,
        message: str,
        level: AlertLevel,
        confidence: Optional[int] = None,
        provenance: Optional[Dict[str, Any]] = None,
        legal_flag: Optional[str] = None
    ) -> Alert:
        """
        Creates, saves, and dispatches a new alert.
        """
        alert = Alert(
            title=title,
            message=message,
            level=level,
            confidence=confidence,
            provenance=provenance or {},
            legal_flag=legal_flag
        )
        
        # 1. Log to console
        color = "white"
        if level == AlertLevel.CRITICAL:
            color = "bold red"
        elif level == AlertLevel.WARNING:
            color = "bold yellow"
        
        console.print(f"[{color}]ALERT ({alert.level}): {alert.title}[/{color}] - {alert.message}")
        
        # 2. Save to persistent log
        self._save_alert(alert)
        
        # 3. Dispatch to webhook (if configured)
        self._dispatch_to_webhook(alert)
        
        logger.info("Dispatched alert %s", alert.id)
        return alert

    def get_alerts(self, status: Optional[AlertStatus] = None) -> List[Alert]:
        """Retrieves alerts from the database, optionally filtering by status."""
        alerts = []
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        alert = Alert(**json.loads(line))
                        if status is None or alert.status == status:
                            alerts.append(alert)
            return sorted(alerts, key=lambda a: a.timestamp, reverse=True)
        except FileNotFoundError:
            return []
        except Exception as e:
            logger.error("Failed to read alerts from %s: %s", self.db_path, e)
            return []

# --- Typer CLI Application ---

alert_app = typer.Typer(name="alerts", help="Manage and view system alerts.")
alert_manager_instance = AlertManager()

@alert_app.command("list")
def list_alerts(
    status: Optional[AlertStatus] = typer.Option(None, "--status", help="Filter by status (new/acknowledged).")
):
    """Lists all dispatched alerts."""
    alerts = alert_manager_instance.get_alerts(status=status)
    if not alerts:
        console.print("[dim]No alerts found.[/dim]")
        return

    for alert in alerts:
        color = "white"
        if alert.level == AlertLevel.CRITICAL:
            color = "red"
        elif alert.level == AlertLevel.WARNING:
            color = "yellow"
        
        console.print(f"--- [bold {color}]Alert ({alert.id})[/bold {color}] ---")
        console.print(f"  [bold]Time:[/bold] {alert.timestamp.isoformat()}")
        console.print(f"  [bold]Level:[/bold] {alert.level.value}")
        console.print(f"  [bold]Title:[/bold] {alert.title}")
        console.print(f"  [bold]Message:[/bold] {alert.message}")
        if alert.confidence:
            console.print(f"  [bold]Confidence:[/bold] {alert.confidence}%")
        if alert.provenance:
            console.print(f"  [bold]Provenance:[/bold] {json.dumps(alert.provenance)}")
        if alert.legal_flag:
            console.print(f"  [bold]Legal Flag:[/bold] {alert.legal_flag}")