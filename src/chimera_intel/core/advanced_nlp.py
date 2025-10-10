from typing import Dict, Any, List, Optional


class AdvancedNLPAnalyzer:
    """
    Performs advanced NLP tasks to detect nuanced conversational features
    beyond basic sentiment and intent.
    """

    def __init__(self):
        """
        Initializes the analyzer with a rulebook of argumentation tactics.
        """
        self.argument_tactics = {
            "appeal_to_authority": {
                "description": "Citing an authority figure or expert to support a claim.",
                "keywords": [
                    "experts say",
                    "studies show",
                    "the industry standard is",
                    "proven by",
                ],
            },
            "social_proof": {
                "description": "Referencing the popularity of an idea as evidence of its validity.",
                "keywords": [
                    "everyone is doing it",
                    "most companies",
                    "the consensus is",
                    "popular choice",
                ],
            },
            "scarcity": {
                "description": "Creating a sense of urgency by highlighting limited availability.",
                "keywords": [
                    "limited time offer",
                    "once it's gone",
                    "few left",
                    "exclusive deal",
                ],
            },
        }

    def detect_argument_tactics(self, message_content: str) -> List[Dict[str, Any]]:
        """
        Analyzes a message to detect the presence of specific argumentation tactics.

        Args:
            message_content (str): The text of the message to analyze.

        Returns:
            A list of detected tactics, if any.
        """
        detected = []
        for tactic_name, tactic_data in self.argument_tactics.items():
            for keyword in tactic_data["keywords"]:
                if keyword in message_content.lower():
                    detected.append(
                        {
                            "tactic": tactic_name,
                            "description": tactic_data["description"],
                            "triggered_by": keyword,
                        }
                    )
        return detected
