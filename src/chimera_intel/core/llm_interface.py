import json
from typing import Dict, Any
import google.generativeai as genai
from .config_loader import API_KEYS
import logging

class LLMInterface:
    """
    Wrapper for interacting with the Gemini API.
    """
    def __init__(self, model: str = "gemini-1.5-flash"):
        """
        Initializes the Gemini client.
        """
        self.api_key = getattr(API_KEYS, "gemini_api_key", None)
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found in your environment configuration.")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(model)

    def generate_message(self, prompt: str, system_role: str = "You are a negotiation assistant.") -> Dict[str, Any]:
        """
        Generates a structured message using the Gemini model.

        Args:
            prompt: The user's prompt, including context and history.
            system_role: The system role to set the context for the model.

        Returns:
            A dictionary containing the structured output from the LLM.
        """
        try:
            # Instruct the model to return a JSON object for structured output
            full_prompt = (
                f"{system_role}\n\n"
                f"{prompt}\n\n"
                "Please provide your response as a single JSON object with the following keys: "
                "'tactic' (e.g., 'strategic concession', 'probing question'), "
                "'message' (the negotiation message), and "
                "'confidence' (a float between 0.0 and 1.0)."
            )
            
            response = self.model.generate_content(full_prompt)
            
            # Clean and parse the JSON response
            cleaned_response = response.text.strip().replace("```json", "").replace("```", "")
            return json.loads(cleaned_response)

        except Exception as e:
            logging.error(f"LLM response generation failed: {e}")
            # Return a structured error to be handled by the agent
            return {
                "tactic": "error",
                "message": f"[LLM_ERROR] Failed to generate or parse response: {e}",
                "confidence": 0.0,
            }

class MockLLMInterface:
    """
    A mock LLM interface for testing purposes.
    This allows for offline testing without making actual API calls.
    """
    def __init__(self, model: str = "mock-gemini"):
        self.model = model

    def generate_message(self, prompt: str, system_role: str = "negotiation assistant") -> Dict[str, Any]:
        """
        Returns a simulated, structured negotiation message.
        """
        # Simulate different responses based on the prompt content for more realistic testing
        if "aggressive" in prompt.lower():
            return {
                "tactic": "Hardball Offer",
                "message": "This is our final offer. We expect a decision by end of day.",
                "confidence": 0.95,
            }
        elif "cooperative" in prompt.lower():
            return {
                "tactic": "Collaborative Proposal",
                "message": "Let's work together to find a price that is fair for both of us. How does $10,500 sound?",
                "confidence": 0.88,
            }
        else:
            return {
                "tactic": "Information Seeking",
                "message": "Thank you for the information. Can you tell me more about your reasoning for that price point?",
                "confidence": 0.92,
            }