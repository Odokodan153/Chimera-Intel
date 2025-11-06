import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.media_forensics_tools import app as media_forensics_app


class MediaForensicsToolsPlugin(ChimeraPlugin):
    """
    Plugin to add media forensics CLI commands.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera media-tools'."""
        return "media-tools"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'media-tools' command."""
        return media_forensics_app

    def initialize(self):
        """
        Initializes the MediaForensicsTools plugin.
        (Tool registration should be handled by the core PluginManager.)
        """
        pass


# The plugin manager will discover and instantiate this class
plugin = MediaForensicsToolsPlugin()