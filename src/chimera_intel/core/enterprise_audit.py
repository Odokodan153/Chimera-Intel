"""
Enterprise Audit (Phase 4)
Wraps the core AuditLogger to provide structured, high-level
audit events for compliance and enterprise logging.
"""

from chimera_intel.core.audit_logger import AuditLogger 
from typing import Dict, Any

class EnterpriseAuditor:
    
    def __init__(self, tenant_id: str):
        """
        Initializes the auditor for a specific tenant.
        """
        self.tenant_id = tenant_id
        # Assuming AuditLogger is a class you can instantiate
        self.logger = AuditLogger() 

    def _log(self, event_type: str, status: str, details: Dict[str, Any]):
        """
        Internal helper to format and log the audit message.
        """
        audit_message = {
            "event_type": event_type,
            "tenant_id": self.tenant_id,
            "status": status,
            **details
        }
        # Assuming your AuditLogger has a generic .log() or .info() method
        self.logger.log_audit(audit_message)

    def log_investigation_start(self, identifier: str, user: str = "system"):
        """Logs the start of a new investigation."""
        self._log(
            event_type="INVESTIGATION_START",
            status="success",
            details={"target": identifier, "user": user}
        )

    def log_report_generation(self, identifier: str, report_paths: Dict[str, str]):
        """Logs the successful generation of a report."""
        self._log(
            event_type="REPORT_GENERATED",
            status="success",
            details={"target": identifier, "paths": report_paths}
        )

    def log_alert_triggered(self, alert_type: str, details: Dict[str, Any]):
        """Logs when an automated alert is triggered."""
        self._log(
            event_type="ALERT_TRIGGERED",
            status="success",
            details={"alert_type": alert_type, **details}
        )

    def log_system_health_fail(self, remediation_steps: list):
        """Logs a failure in the system health check."""
        self._log(
            event_type="SYSTEM_HEALTH",
            status="failure",
            details={"remediation": remediation_steps}
        )