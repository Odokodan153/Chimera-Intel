"""
Image Intelligence & Forensic Detection Pipeline Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.image_forensics_pipeline import pipeline_app

class ImageForensicsPipelinePlugin(ChimeraPlugin):
    """Image Intelligence & Forensic Detection Pipeline plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera image-pipeline')
        return "image-pipeline"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module
        return pipeline_app

    def initialize(self):
        """Initializes the Image Forensics Pipeline plugin."""
        # No specific initialization needed for this plugin
        pass