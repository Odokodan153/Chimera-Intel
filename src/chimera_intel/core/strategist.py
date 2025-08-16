import typer
import json
import google.generativeai as genai # type: ignore
from rich.markdown import Markdown
import logging
from chimera_intel.core.database import get_aggregated_data_for_target
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.utils import console
from chimera_intel.core.schemas import StrategicProfileResult

# Get a logger instance for this specific file

logger = logging.getLogger(__name__)


def generate_strategic_profile(
    aggregated_data: dict, api_key: str
) -> StrategicProfileResult:
    """
    Uses a Generative AI model (Google Gemini Pro) to create a high-level strategic profile.

    Args:
        aggregated_data (dict): The combined OSINT data for the target.
        api_key (str): The Google AI API key for authentication.

    Returns:
        StrategicProfileResult: A Pydantic model containing the AI-generated markdown
                                analysis or an error message.
    """
    if not api_key:
        return StrategicProfileResult(error="GOOGLE_API_KEY not found in .env file.")
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-pro")

    data_str = json.dumps(aggregated_data, indent=2, default=str)

    prompt = f"""
    As an expert business intelligence analyst, your task is to synthesize the following OSINT data into a high-level strategic profile of the target company.
    Focus on deducing their likely strategies based ONLY on the provided data.

    OSINT DATA:
    ```json
    {data_str}
    ```

    Based on the data, provide a concise analysis covering the following points. Present the entire output in Markdown format.
    
    1.  **Marketing & Sales Strategy:** Based on their web technologies, traffic sources, and news, what is their likely go-to-market strategy? Are they targeting consumers (B2C) or businesses (B2B)?
    2.  **Technology & Innovation Strategy:** Based on their tech stack and patents, are they a technology leader, a fast follower, or lagging in their industry? What are their R&D priorities?
    3.  **Expansion & Growth Strategy:** Are there any signals (e.g., in news, financials) that suggest they are planning to expand into new markets, launch new products, or are in a phase of aggressive growth?
    4.  **Overall Summary:** Provide a concluding paragraph summarizing their likely strategic position in the market.
    """

    try:
        response = model.generate_content(prompt)
        return StrategicProfileResult(profile_text=response.text)
    except Exception as e:
        logger.error(
            "An error occurred with the Google AI API during strategy generation: %s", e
        )
        return StrategicProfileResult(
            error=f"An error occurred with the Google AI API: {e}"
        )


# --- Typer CLI Application ---


strategy_app = typer.Typer()


@strategy_app.command("run")
def run_strategy_analysis(
    target: str = typer.Argument(
        ..., help="The target company to analyze (must have historical data)."
    )
):
    """
    Generates an AI-powered strategic profile of a competitor by aggregating all known data.
    """
    logger.info("Generating strategic profile for target: %s", target)

    aggregated_data = get_aggregated_data_for_target(target)

    if not aggregated_data:
        # The get_aggregated_data_for_target function already logs a warning.

        raise typer.Exit(code=1)
    logger.info("Submitting aggregated data to AI strategist for analysis.")
    api_key = API_KEYS.google_api_key
    strategic_result = generate_strategic_profile(aggregated_data, api_key)

    console.print("\n--- [bold]Automated Strategic Profile[/bold] ---\n")
    if strategic_result.error:
        logger.error("Failed to generate strategic profile: %s", strategic_result.error)
    else:
        # Display the AI-generated markdown as rich text in the console

        console.print(
            Markdown(strategic_result.profile_text or "No analysis generated.")
        )
