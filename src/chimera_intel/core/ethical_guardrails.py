from typing import Dict, Any, Optional, List


class EthicalFramework:
    """
    Provides a framework for ensuring negotiation tactics adhere to ethical guidelines.
    """

    def __init__(self):
        """
        Initializes the framework with a predefined set of ethical rules.
        """
        self.rules = {
            "pressure_tactics": {
                "description": "Avoids using undue pressure, artificial deadlines, or threats.",
                "keywords": [
                    "last chance",
                    "final offer",
                    "take it or leave it",
                    "won't find better",
                ],
                "severity": "High",
            },
            "misrepresentation": {
                "description": "Ensures all information presented is truthful and not misleading.",
                "keywords": [
                    "actually believe",
                    "to be honest",
                    "frankly",
                ],  # Can be used deceptively
                "severity": "High",
            },
            "emotional_manipulation": {
                "description": "Avoids appeals to pity, flattery, or guilt.",
                "keywords": [
                    "disappointed",
                    "let down",
                    "unfair to me",
                    "only you can help",
                ],
                "severity": "Medium",
            },
        }

    def check_message(self, message_content: str) -> Optional[Dict[str, Any]]:
        """
        Checks a given message against the ethical rulebook.

        Args:
            message_content (str): The text of the message to check.

        Returns:
            A dictionary describing the violation if one is found, otherwise None.
        """
        for rule_name, rule_data in self.rules.items():
            for keyword in rule_data["keywords"]:
                if keyword in message_content.lower():
                    return {
                        "violation": rule_name,
                        "description": rule_data["description"],
                        "severity": rule_data["severity"],
                        "triggered_by": keyword,
                    }
        return None
