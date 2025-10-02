"""
Defines the interface and base classes for all Chimera Intel plugins.
"""

from abc import ABC, abstractmethod
import typer


class ChimeraPlugin(ABC):
    """Abstract base class for a Chimera Intel plugin."""

    @property
    @abstractmethod
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        pass

    @property
    @abstractmethod
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        pass

    @abstractmethod
    def initialize(self):
        """A method to perform any setup for the plugin."""
        pass
