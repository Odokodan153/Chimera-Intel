import unittest
from unittest.mock import patch
from chimera_intel.core.plugin_manager import discover_plugins
from chimera_intel.core.plugin_interface import ChimeraPlugin
import typer


class MockEntryPoint:
    def __init__(self, name, load_return):
        self.name = name
        self._load_return = load_return

    def load(self):
        if isinstance(self._load_return, Exception):
            raise self._load_return
        return self._load_return


class MockGoodPlugin(ChimeraPlugin):
    @property
    def name(self) -> str:
        return "good_plugin"

    @property
    def app(self) -> typer.Typer:
        return typer.Typer()

    def initialize(self):
        pass


class MockBadPlugin:
    pass


class TestPluginManager(unittest.TestCase):
    """Test cases for the plugin_manager module."""

    @patch("chimera_intel.core.plugin_manager.metadata.entry_points")
    def test_discover_plugins_success(self, mock_entry_points):
        """Tests successful discovery of a valid plugin."""
        mock_entry_points.return_value = [MockEntryPoint("good_plugin", MockGoodPlugin)]
        plugins = discover_plugins()
        self.assertEqual(len(plugins), 1)
        self.assertIsInstance(plugins[0], MockGoodPlugin)

    @patch("chimera_intel.core.plugin_manager.metadata.entry_points")
    def test_discover_plugins_bad_inheritance(self, mock_entry_points):
        """Tests that a plugin not inheriting from ChimeraPlugin is skipped."""
        mock_entry_points.return_value = [MockEntryPoint("bad_plugin", MockBadPlugin)]
        plugins = discover_plugins()
        self.assertEqual(len(plugins), 0)

    @patch("chimera_intel.core.plugin_manager.metadata.entry_points")
    def test_discover_plugins_load_error(self, mock_entry_points):
        """Tests that a plugin that fails to load is skipped."""
        mock_entry_points.return_value = [
            MockEntryPoint("error_plugin", Exception("Load failed"))
        ]
        plugins = discover_plugins()
        self.assertEqual(len(plugins), 0)

    @patch("chimera_intel.core.plugin_manager.metadata.entry_points")
    def test_discover_plugins_entry_point_error(self, mock_entry_points):
        """Tests that an error during entry point discovery is handled."""
        mock_entry_points.side_effect = Exception("Discovery failed")
        plugins = discover_plugins()
        self.assertEqual(len(plugins), 0)
