"""
Plugin for managing and verifying the immutable audit log.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.audit_logger import audit_app

class AuditLoggerPlugin(ChimeraPlugin):
    
    @property
    def name(self) -> str:
        return "audit"

    @property
    def app(self) -> typer.Typer:
        """
        Returns the Typer application for the audit logger.
        """
        return audit_app

    def initialize(self):
        return "Manage and verify the immutable audit log."
