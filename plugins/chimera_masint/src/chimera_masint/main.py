import click
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.masint import masint_cli


class MasintPlugin(ChimeraPlugin):
    """
    Plugin for Measurement and Signature Intelligence (MASINT).
    """

    def get_cli(self) -> click.Group:
        """
        Returns the Click command group for this plugin.
        """
        return masint_cli


# The entry point function that the plugin manager will call
def masint_plugin():
    return MasintPlugin()