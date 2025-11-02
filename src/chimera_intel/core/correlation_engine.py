import logging
from typing import Dict, Any, List
from pydantic import BaseModel, Field
import json

from .schemas import Event
from .plugin_manager import PluginManager

logger = logging.getLogger(__name__)


# --- NEW SCHEMAS ---
# (These would normally be in schemas.py, adding here for clarity)


class PrioritizedAlert(BaseModel):
    """
    An alert produced by the Prioritization Engine, ranking an event.
    """

    event: Event
    priority: str = Field(..., description="High, Medium, or Low")
    confidence: float = Field(
        ..., description="Confidence in the event data (0.0 to 1.0)"
    )
    impact: float = Field(
        ..., description="Potential impact of the event (0.0 to 1.0)"
    )
    ranking_score: float = Field(
        ..., description="Overall calculated score for prioritization"
    )
    domain: str = Field(..., description="The intelligence domain (cyber, finance, personnel, etc.)")


class AutomationPipeline(BaseModel):
    """
    Defines an 'if-this-then-that' automation pipeline.
    """

    name: str
    trigger: Dict[str, Any] = Field(
        ...,
        description="The 'IF' condition to check against a PrioritizedAlert",
    )
    actions: List[Dict[str, Any]] = Field(
        ..., description="The 'THEN-THAT' actions to execute"
    )


# --- NEW: ALERT PRIORITIZATION ENGINE ---


class AlertPrioritizationEngine:
    """
    AI-driven engine to rank signals by relevance, confidence, and impact.
    """

    def __init__(self, weights: Dict[str, Any]):
        self.impact_weight = weights.get("impact", 0.5)
        self.confidence_weight = weights.get("confidence", 0.3)
        self.relevance_weight = weights.get("relevance", 0.2)
        logger.info(
            f"Prioritization Engine initialized with weights: Impact={self.impact_weight}, "
            f"Confidence={self.confidence_weight}, Relevance={self.relevance_weight}"
        )

    def _calculate_impact(self, event: Event) -> float:
        """Calculates potential impact based on event data."""
        # --- Multi-Domain Impact Logic ---
        if event.event_type == "vulnerability_scan":
            # Example: Cyber Domain
            cvss_score = event.details.get("cvss_score", 0.0)
            return cvss_score / 10.0  # Normalize (0.0 - 1.0)
        elif event.event_type == "personnel_report":
            # Example: Personnel Domain
            if event.details.get("is_insider_threat"):
                return 1.0
            return 0.3
        elif event.event_type == "finance_anomaly":
            # Example: Finance Domain
            if event.details.get("is_large_transfer"):
                return 0.8
            return 0.4
        return 0.2  # Default low impact

    def _calculate_confidence(self, event: Event) -> float:
        """Calculates confidence based on source or event type."""
        # (This can be expanded with a source reputation model)
        if event.source == "vulnerability_scanner":
            return 0.9  # High confidence
        if event.source == "social_media_listener":
            return 0.5  # Lower confidence
        return 0.7  # Default

    def _calculate_relevance(self, event: Event) -> float:
        """Calculates relevance to the organization's assets."""
        # (This can be expanded to check against a project's asset database)
        if event.details.get("is_critical_asset"):
            return 1.0
        return 0.5  # Default

    def prioritize_alert(self, event: Event) -> PrioritizedAlert:
        """
        Processes a raw event and returns a PrioritizedAlert.
        """
        impact = self._calculate_impact(event)
        confidence = self._calculate_confidence(event)
        relevance = self._calculate_relevance(event)

        # Calculate final ranking score
        score = (
            (impact * self.impact_weight)
            + (confidence * self.confidence_weight)
            + (relevance * self.relevance_weight)
        )

        if score >= 0.7:
            priority = "High"
        elif score >= 0.4:
            priority = "Medium"
        else:
            priority = "Low"

        # Determine domain
        domain = "cyber" # Default
        if "finance" in event.event_type:
            domain = "finance"
        elif "personnel" in event.event_type:
            domain = "personnel"
        elif "physical" in event.event_type:
            domain = "physical"
            
        return PrioritizedAlert(
            event=event,
            priority=priority,
            confidence=confidence,
            impact=impact,
            ranking_score=score,
            domain=domain,
        )


# --- MODIFIED: CORRELATION ENGINE ---


class CorrelationEngine:
    """
    Correlates security events to identify complex threats and trigger automated responses.
    Now runs Automation Pipelines and uses the Alert Prioritization Engine.
    """

    def __init__(self, plugin_manager: PluginManager, config: Dict[str, Any]):
        self.plugin_manager = plugin_manager
        
        # 1. Load the new Prioritization Engine
        self.prioritization_engine = AlertPrioritizationEngine(
            config.get("prioritization_weights", {})
        )

        # 2. Load the new Automation Pipelines (IFTTT)
        self.pipelines: List[AutomationPipeline] = []
        pipeline_configs = config.get("automation_pipelines", {}).get("pipelines", [])
        for p_config in pipeline_configs:
            try:
                self.pipelines.append(AutomationPipeline.model_validate(p_config))
            except Exception as e:
                logger.error(
                    f"Failed to load automation pipeline '{p_config.get('name')}': {e}"
                )
        
        # 3. Load TTP Knowledge Base (for cross-module correlation)
        self.ttp_knowledge_base = config.get("ttp_knowledge_base", {})
        logger.info(f"Correlation Engine loaded {len(self.pipelines)} pipelines.")


    def process_event(self, event: Event) -> None:
        """
        Processes a single event:
        1. Prioritizes the event into an alert.
        2. Checks for matching automation pipelines.
        """
        logger.info(f"Processing event: {event.event_type} from {event.source}")
        
        # --- 1. Prioritize Event ---
        prioritized_alert = self.prioritization_engine.prioritize_alert(event)
        logger.info(
            f"Event {event.id} prioritized: Score={prioritized_alert.ranking_score:.2f}, "
            f"Priority={prioritized_alert.priority}"
        )
        
        # --- 2. Check Automation Pipelines ---
        for pipeline in self.pipelines:
            if self._pipeline_matches(prioritized_alert, pipeline):
                self._handle_match(prioritized_alert, pipeline)

    def _pipeline_matches(
        self, alert: PrioritizedAlert, pipeline: AutomationPipeline
    ) -> bool:
        """
        Checks if a prioritized alert matches the 'IF' trigger of a pipeline.
        This enables Cross-Module Correlation by checking event data from any domain.
        """
        trigger = pipeline.trigger

        for key, value in trigger.items():
            # Check against the alert object (e.g., "priority", "ranking_score")
            if hasattr(alert, key):
                alert_value = getattr(alert, key)
                # Add basic comparison logic (e.g., "ranking_score >= 0.8")
                if isinstance(value, str) and value.startswith((">=", "<=", ">", "<")):
                    try:
                        operator = value.split(" ")[0]
                        threshold = float(value.split(" ")[1])
                        if operator == ">=" and not (alert_value >= threshold):
                            return False
                        if operator == "<=" and not (alert_value <= threshold):
                            return False
                        if operator == ">" and not (alert_value > threshold):
                            return False
                        if operator == "<" and not (alert_value < threshold):
                            return False
                    except Exception:
                        return False # Failed comparison
                elif alert_value != value:
                    return False
            # Check against the original event (e.g., "event.event_type")
            elif key.startswith("event."):
                event_key = key.split("event.", 1)[1]
                event_value = getattr(alert.event, event_key, None)
                
                # Check nested details (e.g., "event.details.cvss_score")
                if "." in event_key:
                    parts = event_key.split(".")
                    if parts[0] == "details":
                        event_value = alert.event.details.get(parts[1])

                if event_value != value:
                    return False
            else:
                return False # Key not found on alert or event
        return True # All trigger conditions matched

    def _handle_match(self, alert: PrioritizedAlert, pipeline: AutomationPipeline) -> None:
        """
        Handles a matched pipeline by executing the 'THEN-THAT' actions.
        """
        logger.info(
            f"Pipeline '{pipeline.name}' matched for event {alert.event.id}. Executing actions."
        )
        for action in pipeline.actions:
            action_type = action.get("type")
            if action_type == "trigger_scan":
                self._trigger_scan(
                    action.get("params", []),
                    pipeline.name,
                    alert.event,  # Pass the original event for templating
                )
            elif action_type == "ttp_lookup":
                self._ttp_lookup(alert.event, action)
            elif action_type == "log_alert":
                logger.warning(f"HIGH PRIORITY ALERT: {action.get('message')}")

    def _trigger_scan(
        self, params: List[str], description: str, event: Event
    ) -> None:
        """
        Triggers a plugin command (no change from original).
        """
        if not params:
            logger.error("Trigger scan action requires parameters.")
            return
        plugin_name = params[0]
        command = params[1]
        args_template = params[2:]

        args = []
        for arg in args_template:
            if arg.startswith("{") and arg.endswith("}"):
                key = arg[1:-1]
                value = None
                if key.startswith("details."):
                    detail_key = key.split("details.", 1)[1]
                    value = event.details.get(detail_key)
                else:
                    value = event.details.get(key) or getattr(event, key, None)

                if value:
                    args.append(str(value))
                else:
                    logger.warning(f"Template key {arg} not found in event.")
                    args.append(arg)
            else:
                args.append(arg)

        logger.info(
            f"Triggering scan '{command}' from plugin '{plugin_name}' with args {args}. Reason: {description}"
        )
        try:
            self.plugin_manager.run_command(plugin_name, command, *args)
        except Exception as e:
            logger.error(f"Failed to trigger scan '{command}' on '{plugin_name}': {e}")

    def _ttp_lookup(self, event: Event, action: Dict[str, Any]):
        """
        Performs a TTP lookup based on event data (no change from original).
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
            if action.get("trigger_on_find"):
                params = action["trigger_on_find"].get("params", [])
                description = (
                    f"Critical CVE {cve_id} found on {event.details.get('source_ip')}"
                )
                self._trigger_scan(params, description, event)