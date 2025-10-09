# src/chimera_intel/core/gemini_client.py


import logging
import os
import time
import random
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

logger = logging.getLogger(__name__)

# --- API Key Validation ---

try:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        # Enforce API key presence by raising an exception

        raise ValueError("FATAL: GEMINI_API_KEY environment variable is not set.")
    genai.configure(api_key=api_key)
    logger.info("Gemini API key configured successfully.")
except ValueError as e:
    logger.error(e)
    # This will stop the application if the key is missing

    raise


def call_gemini_api(prompt: str, retries: int = 3, initial_delay: int = 5) -> str:
    """
    Sends a prompt to the Gemini API with exponential backoff and jitter.
    """
    delay = initial_delay
    for attempt in range(retries):
        try:
            model = genai.GenerativeModel("gemini-pro")
            # Safety settings should be reviewed and adjusted for production

            response = model.generate_content(
                prompt,
                safety_settings={
                    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                },
            )
            return response.text
        except Exception as e:
            logger.warning(
                f"Gemini API call failed on attempt {attempt + 1}/{retries}: {e}"
            )
            if attempt < retries - 1:
                # Exponential backoff with jitter

                backoff_time = delay * (2**attempt) + random.uniform(0, 1)
                time.sleep(backoff_time)
            else:
                logger.error("All Gemini API retries failed.")
                return ""  # Return empty string on final failure
