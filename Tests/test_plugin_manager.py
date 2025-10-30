import unittest
from unittest.mock import patch, MagicMock
import typer

from chimera_intel.core.plugin_manager import discover_plugins
from chimera_intel.core.plugin_interface import ChimeraPlugin


# --- Mock Plugin Classes for Testing ---


class ValidPluginA(ChimeraPlugin):
    """A valid mock plugin."""

    @property
    def name(self) -> str:
        return "plugin_a"

    @property
    def app(self) -> typer.Typer:
        return typer.Typer()

    def initialize(self):
        # This method can be spied on to ensure it was called

        pass


class ValidPluginB(ChimeraPlugin):
    """Another valid mock plugin."""

    @property
    def name(self) -> str:
        return "plugin_b"

    @property
    def app(self) -> typer.Typer:
        return typer.Typer()

    def initialize(self):
        pass


class InvalidPlugin:
    """An invalid mock plugin that does not inherit from ChimeraPlugin."""

    name = "invalid_plugin"


class FailingPlugin(ChimeraPlugin):
    """A mock plugin that raises an exception during initialization."""

    @property
    def name(self) -> str:
        return "failing_plugin"

    @property
    def app(self) -> typer.Typer:
        return typer.Typer()

    def initialize(self):
        raise RuntimeError("Failed to initialize")


class TestPluginManager(unittest.TestCase):
    """Test cases for the dynamic plugin discovery and loading mechanism."""

    @patch("importlib.metadata.entry_points")
    def test_discover_plugins_success(self, mock_entry_points):
        """Tests the successful discovery and loading of valid plugins."""
        # Arrange

        mock_entry_point_a = MagicMock()
        mock_entry_point_a.load.return_value = ValidPluginA

        mock_entry_point_b = MagicMock()
        mock_entry_point_b.load.return_value = ValidPluginB

        mock_entry_points.return_value = [mock_entry_point_a, mock_entry_point_b]

        # Spy on the initialize method

        with (
            patch.object(
                ValidPluginA, "initialize", wraps=ValidPluginA().initialize
            ) as spy_a,
            patch.object(
                ValidPluginB, "initialize", wraps=ValidPluginB().initialize
            ) as spy_b,
        ):

            # Act

            plugins = discover_plugins()

            # Assert

            self.assertEqual(len(plugins), 2)
            self.assertIsInstance(plugins[0], ValidPluginA)
            self.assertIsInstance(plugins[1], ValidPluginB)
            spy_a.assert_called_once()
            spy_b.assert_called_once()

    @patch("importlib.metadata.entry_points")
    def test_discover_plugins_skips_invalid_plugins(self, mock_entry_points):
        """Tests that the discovery process gracefully skips invalid (non-subclass) plugins."""
        # Arrange

        mock_valid_entry = MagicMock()
        mock_valid_entry.load.return_value = ValidPluginA

        mock_invalid_entry = MagicMock()
        mock_invalid_entry.load.return_value = InvalidPlugin

        mock_entry_points.return_value = [mock_valid_entry, mock_invalid_entry]

        # Act

        plugins = discover_plugins()

        # Assert

        self.assertEqual(len(plugins), 1)
        self.assertIsInstance(plugins[0], ValidPluginA)

    @patch("importlib.metadata.entry_points")
    def test_discover_plugins_handles_loading_errors(self, mock_entry_points):
        """Tests that the manager handles exceptions raised during a plugin's initialization."""
        # Arrange

        mock_valid_entry = MagicMock()
        mock_valid_entry.load.return_value = ValidPluginA

        mock_failing_entry = MagicMock()
        mock_failing_entry.load.return_value = FailingPlugin

        mock_entry_points.return_value = [mock_valid_entry, mock_failing_entry]

        # Act

        plugins = discover_plugins()

        # Assert
        # Should only load the valid plugin and skip the one that failed.

        self.assertEqual(len(plugins), 1)
        self.assertIsInstance(plugins[0], ValidPluginA)

    @patch("importlib.metadata.entry_points")
    def test_discover_plugins_no_plugins_found(self, mock_entry_points):
        """Tests the scenario where no plugins are found."""
        # Arrange

        mock_entry_points.return_value = []

        # Act

        plugins = discover_plugins()

        # Assert

        self.assertEqual(len(plugins), 0)


if __name__ == "__main__":
    unittest.main()
