"""
Communications Intelligence (COMINT) Plugin for Chimera Intel.
"""

import typer
import logging
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.comint import COMINTModule, cli_app
from chimera_intel.core.ai_core import AICore
from chimera_intel.core.advanced_nlp import AdvancedNLP
from chimera_intel.core.arg_service import ArgService
from chimera_intel.core.adversary_voice_matcher import AdversaryVoiceMatcher
from typing import Optional

logger = logging.getLogger(__name__)

class COMINTPlugin(ChimeraPlugin):
    """
    Plugin for Communications Intelligence (COMINT).
    
    Orchestrates modules for:
    - Deep Packet Inspection (DPI) on PCAP files
    - NLP analysis of intercepted text
    - Correlation of communication patterns in the graph
    - Speaker identification on intercepted audio
    """

    def __init__(self):
        super().__init__()
        self.comint_module: Optional[COMINTModule] = None

    @property
    def name(self) -> str:
        """This defines the top-level command name: 'chimera comint'"""
        return "comint"

    @property
    def app(self) -> typer.Typer:
        """This points to the Typer app instance in the core module."""
        return cli_app

    def get_dependencies(self) -> list:
        """
        List the core modules this plugin depends on.
        The plugin manager will provide these to `initialize`.
        """
        return [AICore, AdvancedNLP, ArgService, AdversaryVoiceMatcher]

    def initialize(self, dependencies: dict):
        """
        Initialize the COMINT module with its dependencies.
        """
        try:
            # Get required dependencies from the provided map
            ai_core = dependencies.get(AICore)
            nlp_processor = dependencies.get(AdvancedNLP)
            arg_service = dependencies.get(ArgService)
            voice_matcher = dependencies.get(AdversaryVoiceMatcher)

            if not all([ai_core, nlp_processor, arg_service, voice_matcher]):
                logger.error("Missing one or more dependencies for COMINTPlugin. Failed to initialize.")
                return

            # Initialize the core module
            self.comint_module = COMINTModule(
                ai_core=ai_core,
                nlp_processor=nlp_processor,
                arg_service=arg_service,
                voice_matcher=voice_matcher
            )
            logger.info("COMINTPlugin initialized successfully.")
        except Exception as e:
            logger.error(f"Error initializing COMINTPlugin: {e}", exc_info=True)

    def add_to_context(self, context: dict) -> dict:
        """
        Add the module instance to the CLI context object,
        making it available to the `comint` commands.
        """
        if self.comint_module:
            context["comint_module"] = self.comint_module
        return context