"""
Plugin Manager for dynamically discovering and loading Chimera Intel plugins.
"""

import importlib.metadata as metadata
import logging
from typing import List, Dict, Any
from .plugin_interface import ChimeraPlugin

logger = logging.getLogger(__name__)


class PluginManager:
    """
    Manages the discovery, loading, and execution of Chimera Intel plugins.
    """

    def __init__(self):
        """
        Initializes the PluginManager and discovers all available plugins.
        """
        self.plugins: Dict[str, ChimeraPlugin] = self._discover_plugins()

    def _discover_plugins(self) -> Dict[str, ChimeraPlugin]:
        """
        Discovers all installed plugins using the 'chimera_intel.plugins' entry point.

        Returns:
            A dictionary of instantiated plugin objects, with plugin names as keys.
        """
        plugins: Dict[str, ChimeraPlugin] = {}
        logger.info("Discovering plugins...")

        try:
            entry_points = metadata.entry_points(group="chimera_intel.plugins")
            for entry_point in entry_points:
                try:
                    plugin_class = entry_point.load()
                    plugin_instance = plugin_class()
                    if isinstance(plugin_instance, ChimeraPlugin):
                        plugin_instance.initialize()
                        if plugin_instance.name in plugins:
                            logger.warning(
                                f"Duplicate plugin name '{plugin_instance.name}' found. Overwriting."
                            )
                        plugins[plugin_instance.name] = plugin_instance
                        logger.info(
                            f"Successfully loaded plugin: {plugin_instance.name}"
                        )
                    else:
                        logger.warning(
                            f"Plugin {entry_point.name} does not inherit from ChimeraPlugin."
                        )
                except Exception as e:
                    logger.error(
                        f"Failed to load plugin {entry_point.name}: {e}", exc_info=True
                    )
        except Exception as e:
            logger.error(
                f"An error occurred during plugin discovery: {e}", exc_info=True
            )
        logger.info(f"Discovered {len(plugins)} plugins.")
        return plugins

    def get_plugin(self, plugin_name: str) -> ChimeraPlugin | None:
        """
        Retrieves a plugin by its name.

        Args:
            plugin_name: The name of the plugin to retrieve.

        Returns:
            The plugin instance, or None if not found.
        """
        return self.plugins.get(plugin_name)

    def get_all_plugins(self) -> List[ChimeraPlugin]:
        """
        Returns a list of all discovered plugins.
        """
        return list(self.plugins.values())

    def run_command(
        self, plugin_name: str, command: str, *args: Any, **kwargs: Any
    ) -> Any:
        """
        Runs a command on a specific plugin.

        Args:
            plugin_name: The name of the plugin.
            command: The command to run.
            *args: Positional arguments for the command.
            **kwargs: Keyword arguments for the command.

        Returns:
            The result of the command execution.

        Raises:
            ValueError: If the plugin is not found.
            NotImplementedError: If the plugin does not support the command.
        """
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            raise ValueError(f"Plugin '{plugin_name}' not found.")
        try:
            # Assumes that plugins have a generic `execute_command` method.
            # You might need to adjust this based on your plugin interface.

            if hasattr(plugin, command) and callable(getattr(plugin, command)):
                return getattr(plugin, command)(*args, **kwargs)
            else:
                raise NotImplementedError(
                    f"Plugin '{plugin_name}' does not have a command '{command}'."
                )
        except Exception as e:
            logger.error(
                f"Error running command '{command}' on plugin '{plugin_name}': {e}",
                exc_info=True,
            )
            raise


def discover_plugins() -> List[ChimeraPlugin]:
    """
    Discovers all installed plugins using the 'chimera_intel.plugins' entry point.

    This function is kept for backward compatibility or for scenarios where
    only a list of plugins is needed without the management capabilities of PluginManager.

    Returns:
        A list of instantiated plugin objects.
    """
    manager = PluginManager()
    return manager.get_all_plugins()
