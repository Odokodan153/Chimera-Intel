"""
Media Hardening Plugin for Chimera Intel.

This plugin provides defensive measures for media assets, including
watermarking, provenance tracking (C2PA), and secure vault management.
"""

import typer
import logging
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.config_loader import ConfigLoader

# Import the service, the app, and the global instance variable
from chimera_intel.core.media_hardening import (
    MediaHardeningService, 
    media_hardening_app, 
    media_hardening_service_instance as core_service_instance_ref
)

logger = logging.getLogger(__name__)

class MediaHardeningPlugin(ChimeraPlugin):
    """Media Hardening plugin wrapper."""

    @property
    def name(self) -> str:
        """This defines the command name (e.g., 'chimera harden')."""
        return "harden"

    @property
    def app(self) -> typer.Typer:
        """This points to the existing Typer app instance in the core module."""
        return media_hardening_app

    def initialize(self, config: ConfigLoader):
        """
        Initializes the Media Hardening plugin.
        
        This method reads the config, creates the MediaHardeningService,
        and injects it into the core module's global variable for the
        Typer commands to access.
        """
        global core_service_instance_ref
        
        try:
            vault_path = config.get_setting("media_hardening.vault_path", "secure_media_vault")
            watermark_text = config.get_setting("media_hardening.watermark_text", "CHIMERA-INTEL // CONFIDENTIAL")
            opsec_brief_path = config.get_setting("media_hardening.opsec_brief_path", "src/chimera_intel/core/opsec_brief.json")
            c2pa_cert_path = config.get_setting("media_hardening.c2pa_cert_path")
            c2pa_key_path = config.get_setting("media_hardening.c2pa_key_path")

            if not c2pa_cert_path or not c2pa_key_path:
                logger.error("media_hardening.c2pa_cert_path or media_hardening.c2pa_key_path not set in config.yaml.")
                logger.error("C2PA embedding functionality will fail.")
            
            # Create the service instance
            service = MediaHardeningService(
                vault_path=vault_path,
                watermark_text=watermark_text,
                opsec_brief_path=opsec_brief_path,
                c2pa_cert_path=c2pa_cert_path,
                c2pa_key_path=c2pa_key_path
            )
            
            # Set the global instance in the core module
            # We must modify the imported module directly
            import chimera_intel.core.media_hardening
            chimera_intel.core.media_hardening.media_hardening_service_instance = service
            
            logger.info("Media Hardening Plugin initialized and service injected.")

        except ImportError as e:
            logger.error(f"Failed to initialize MediaHardeningPlugin. Missing dependency: {e}")
            logger.error("Please install: pip install c2pa imwatermark opencv-python numpy")
        except Exception as e:
            logger.error(f"Error initializing MediaHardeningPlugin: {e}")