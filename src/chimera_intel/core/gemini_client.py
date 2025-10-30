import google.generativeai as genai
import logging
from .config_loader import API_KEYS


class GeminiClient:
    """A client for interacting with the Google Gemini API."""

    def __init__(self):
        """Initializes the Gemini client and configures the API key."""
        self.api_key = getattr(API_KEYS, "google_api_key", None)
        if not self.api_key:
            logging.error("Gemini API key not found in configuration.")
            self.model = None
            return
        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel("gemini-1.5-flash")
        except Exception as e:
            logging.error(f"Failed to configure Gemini client: {e}")
            self.model = None

    def classify_intent(self, message: str) -> str:
        """
        Classifies the intent of a message using the Gemini API.

        Args:
            message (str): The message to classify.

        Returns:
            The classified intent as a string, or "unknown" if classification fails.
        """
        if not self.model:
            return "unknown"
        try:
            prompt = f"Classify the intent of the following message into one of these categories: offer, condition, rejection, discussion, acceptance. Message: '{message}'"
            response = self.model.generate_content(prompt)
            return response.text.strip().lower()
        except Exception as e:
            logging.error(f"Gemini intent classification failed: {e}")
            return "unknown"

    def generate_response(self, persona_prompt: str) -> str:
        """
        Generates a bot response using the Gemini API based on a persona.

        Args:
            persona_prompt (str): The prompt defining the persona and context.

        Returns:
            The generated response, or a fallback message if generation fails.
        """
        if not self.model:
            return "I am not available to respond right now."
        try:
            response = self.model.generate_content(persona_prompt)
            return response.text.strip()
        except Exception as e:
            logging.error(f"Gemini response generation failed: {e}")
            return (
                "I am having trouble formulating a response. Could you please rephrase?"
            )
