"""
Plugin Manager for dynamically discovering and loading Chimera Intel plugins.
"""

import importlib.metadata as metadata
import logging
from typing import List
from .plugin_interface import ChimeraPlugin

logger = logging.getLogger(__name__)


def discover_plugins() -> List[ChimeraPlugin]:
    """
    Discovers all installed plugins using the 'chimera_intel.plugins' entry point.

    Returns:
        List[ChimeraPlugin]: A list of instantiated plugin objects.
    """
    plugins: List[ChimeraPlugin] = []

    try:
        entry_points = metadata.entry_points(group="chimera_intel.plugins")
        for entry_point in entry_points:
            try:
                plugin_class = entry_point.load()
                plugin_instance = plugin_class()
                if isinstance(plugin_instance, ChimeraPlugin):
                    plugin_instance.initialize()
                    plugins.append(plugin_instance)
                    logger.info(f"Successfully loaded plugin: {plugin_instance.name}")
                else:
                    logger.warning(
                        f"Plugin {entry_point.name} does not inherit from ChimeraPlugin."
                    )
            except Exception as e:
                logger.error(f"Failed to load plugin {entry_point.name}: {e}")
    except Exception as e:
        logger.error(f"An error occurred during plugin discovery: {e}")
    return plugins
