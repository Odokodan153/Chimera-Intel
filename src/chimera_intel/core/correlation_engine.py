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
        # FIX: Correctly parse rules and TTP base from the main config dict
        self.rules = config.get("correlation_rules", {}).get("rules", [])
        self.ttp_knowledge_base = config.get("ttp_knowledge_base", {})

    def process_event(self, event: Event) -> None:
        """
        Processes a single event and checks for correlation triggers.

        Args:
            event: The event to be processed.
        """
        logger.info(f"Processing event: {event.event_type} from {event.source}")
        # FIX: Iterate over self.rules (the list)
        for rule in self.rules:
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
                    action.get("params", []),
                    rule.get("description", ""),
                    event,  # FIX: Pass the event for templating
                )
            elif action_type == "ttp_lookup":
                self._ttp_lookup(event, action)

    def _trigger_scan(
        self, params: List[str], description: str, event: Event
    ) -> None:  # FIX: Accept event
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
        args_template = params[2:]

        # FIX: Add template replacement logic
        args = []
        for arg in args_template:
            if arg.startswith("{") and arg.endswith("}"):
                key = arg[1:-1]  # e.g., "details.new_ip" or "cve_id"
                value = None
                if key.startswith("details."):
                    detail_key = key.split("details.", 1)[1]
                    value = event.details.get(detail_key)
                else:
                    # Check details first, then root event object
                    value = event.details.get(key) or getattr(event, key, None)

                if value:
                    args.append(str(value))
                else:
                    logger.warning(f"Template key {arg} not found in event.")
                    args.append(arg)  # Keep template if no value
            else:
                args.append(arg)

        logger.info(
            f"Triggering scan '{command}' from plugin '{plugin_name}' with args {args}. Reason: {description}"
        )
        try:
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
        ttp_info = self.ttp_knowledge_base.get(cve_id)  # This will now work
        if ttp_info:
            message = (
                f"TTP found for {cve_id}: {ttp_info['name']} ({ttp_info['attack_id']})."
            )
            logger.info(message)

            if action.get("trigger_on_find"):
                params = action["trigger_on_find"].get("params", [])
                description = (
                    f"Critical CVE {cve_id} found on {event.details.get('source_ip')}"
                )
                # FIX: Call the main trigger_scan function, which now handles templating
                self._trigger_scan(params, description, event)
