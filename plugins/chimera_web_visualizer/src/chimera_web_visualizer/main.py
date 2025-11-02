"""
Web Visual Diff Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.web_visual_diff import web_visual_diff_app


class WebVisualDiffPlugin(ChimeraPlugin):
    """Plugin for visually comparing web page screenshots."""

    @property
    def name(self) -> str:
        return "visual-diff"

    @property
    def app(self) -> typer.Typer:
        return web_visual_diff_app

    def initialize(self):
        """Check for pillow dependency, though it's checked in the module."""
        pass