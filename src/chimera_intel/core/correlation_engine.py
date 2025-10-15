import logging
from typing import Dict, Any, List
from .schemas import Event
from .plugin_manager import PluginManager

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
    Correlates security events to identify complex threats and trigger automated responses.
    """

    def __init__(self, plugin_manager: PluginManager, config: Dict[str, Any]):
        self.plugin_manager = plugin_manager
        self.config = config.get("correlation_rules", [])
        self.ttp_knowledge_base = self._load_ttp_knowledge_base()

    def _load_ttp_knowledge_base(self) -> Dict[str, Any]:
        """Loads TTP knowledge base from configuration."""
        # In a real system, this would load from a comprehensive, up-to-date source.

        return self.config.get("ttp_knowledge_base", {})

    def process_event(self, event: Event) -> None:
        """
        Processes a single event and checks for correlation triggers.

        Args:
            event: The event to be processed.
        """
        logger.info(f"Processing event: {event.event_type} from {event.source}")
        for rule in self.config.get("rules", []):
            if self._rule_matches(event, rule):
                self._handle_match(event, rule)

    def _rule_matches(self, event: Event, rule: Dict[str, Any]) -> bool:
        """
        Checks if an event matches the conditions of a correlation rule.
        """
        conditions = rule.get("conditions", {})

        # Simple matching logic, can be expanded to support more complex queries

        for key, value in conditions.items():
            if getattr(event, key, None) != value:
                return False
        return True

    def _handle_match(self, event: Event, rule: Dict[str, Any]) -> None:
        """
        Handles a matched rule by executing the defined actions.
        """
        logger.info(f"Rule '{rule['name']}' matched for event {event.id}")
        for action in rule.get("actions", []):
            action_type = action.get("type")
            if action_type == "trigger_scan":
                self._trigger_scan(
                    action.get("params", []), rule.get("description", "")
                )
            elif action_type == "ttp_lookup":
                self._ttp_lookup(event, action)

    def _trigger_scan(self, params: List[str], description: str) -> None:
        """
        Triggers a plugin command.
        """
        if not params:
            logger.error(
                "Trigger scan action requires parameters (plugin name, command, args...)."
            )
            return
        plugin_name = params[0]
        command = params[1]
        args = params[2:]

        logger.info(
            f"Triggering scan '{command}' from plugin '{plugin_name}' with args {args}. Reason: {description}"
        )
        try:
            # This is a simplified call. A real implementation would handle plugin execution
            # context, state, and potential return values more robustly.

            self.plugin_manager.run_command(plugin_name, command, *args)
            logger.info(f"Successfully triggered scan '{command}' on '{plugin_name}'.")
        except Exception as e:
            logger.error(f"Failed to trigger scan '{command}' on '{plugin_name}': {e}")

    def _ttp_lookup(self, event: Event, action: Dict[str, Any]):
        """
        Performs a TTP lookup based on event data.
        """
        cve_id = event.details.get("cve_id")
        if not cve_id:
            return
        ttp_info = self.ttp_knowledge_base.get(cve_id)
        if ttp_info:
            message = (
                f"TTP found for {cve_id}: {ttp_info['name']} ({ttp_info['attack_id']})."
            )
            logger.info(message)

            # Example of chaining actions: trigger a scan based on TTP lookup

            if action.get("trigger_on_find"):
                params = action["trigger_on_find"].get("params", [])
                # Customize params with event data, e.g., mapping CVE to a specific scan

                custom_params = [p.replace("{cve_id}", cve_id) for p in params]
                description = (
                    f"Critical CVE {cve_id} found on {event.details.get('source_ip')}"
                )
                self._trigger_scan(custom_params, description)
