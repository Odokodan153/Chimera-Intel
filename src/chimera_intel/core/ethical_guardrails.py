from typing import Dict, Any, Optional, List
import json
import logging


class EthicalFramework:
    """
    Provides a framework for ensuring negotiation tactics adhere to ethical guidelines.
    """

    def __init__(self, rules_filepath: Optional[str] = None):
        """
        Initializes the framework with a predefined set of ethical rules.
        Rules can be loaded from a JSON file or use a default set.
        """
        if rules_filepath:
            try:
                with open(rules_filepath, "r") as f:
                    self.rules = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logging.error(
                    f"Failed to load ethical rules from {rules_filepath}: {e}"
                )
                self.rules = self._get_default_rules()
        else:
            self.rules = self._get_default_rules()

    def _get_default_rules(self) -> Dict[str, Any]:
        """Returns a default set of ethical rules."""
        return {
            "pressure_tactics": {
                "description": "Avoids using undue pressure, artificial deadlines, or threats.",
                "keywords": [
                    "last chance",
                    "final offer",
                    "take it or leave it",
                    "won't find a better deal",
                    "act now",
                    "limited time",
                ],
                "severity": "High",
            },
            "misrepresentation": {
                "description": "Ensures all information presented is truthful and not misleading.",
                "keywords": [
                    "to be honest",
                    "frankly",
                    "believe me",
                    "I can assure you",
                ],  # Can be used deceptively
                "severity": "High",
            },
            "emotional_manipulation": {
                "description": "Avoids appeals to pity, flattery, or guilt.",
                "keywords": [
                    "disappointed in you",
                    "you owe me",
                    "let us down",
                    "unfair to me",
                    "don't be difficult",
                ],
                "severity": "Medium",
            },
            "information_hiding": {
                "description": "Avoids deliberately withholding critical information.",
                "keywords": [
                    "that's not important",
                    "let's not get into details",
                    "focus on the main point",
                ],
                "severity": "Medium",
            },
        }

    def check_message(self, message_content: str) -> List[Dict[str, Any]]:
        """
        Checks a given message against the ethical rulebook.

        Args:
            message_content: The text of the message to be checked.

        Returns:
            A list of dictionaries, where each dictionary represents a detected
            ethical violation. Returns an empty list if no violations are found.
        """
        violations = []
        message_lower = message_content.lower()
        for rule_name, rule_data in self.rules.items():
            for keyword in rule_data["keywords"]:
                if keyword in message_lower:
                    violations.append(
                        {
                            "violation": rule_name,
                            "description": rule_data["description"],
                            "severity": rule_data["severity"],
                            "triggered_by": keyword,
                        }
                    )
        return violations
