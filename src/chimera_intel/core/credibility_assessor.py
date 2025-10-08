import logging
import asyncio
from typing import Optional, List
from pydantic import BaseModel, Field
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import typer
from rich.console import Console
from rich.panel import Panel
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)

# --- Data Schemas ---


class CredibilityResult(BaseModel):
    """
    Represents the result of a credibility assessment.
    """

    url: str = Field(..., description="The URL that was assessed.")
    credibility_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="A score from 0 (not credible) to 10 (highly credible).",
    )
    factors: List[str] = Field(
        ..., description="A list of factors that contributed to the score."
    )
    error: Optional[str] = Field(
        None, description="Any error that occurred during the assessment."
    )


# --- Core Logic ---


async def check_google_safe_browsing(url: str) -> Optional[dict]:
    # ... (function logic remains the same)

    api_key = API_KEYS.google_api_key
    if not api_key:
        return None
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "chimera-intel", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(api_url, json=payload)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"Google Safe Browsing API error: {e}")
            return None


async def assess_source_credibility(url: str) -> CredibilityResult:
    # ... (function logic remains the same)

    factors = []
    score = 5.0  # Start with a neutral score

    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # 1. SSL Certificate

        if url.startswith("https://"):
            score += 1.0
            factors.append("SSL certificate is present.")
        else:
            score -= 2.0
            factors.append("No SSL certificate, which is a major security risk.")
        # 2. Domain Age

        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = (
                    domain_info.creation_date[0]
                    if isinstance(domain_info.creation_date, list)
                    else domain_info.creation_date
                )
                age = (datetime.now() - creation_date).days / 365
                if age > 2:
                    score += 1.0
                    factors.append(f"Domain is mature ({age:.1f} years old).")
                elif age < 1:
                    score -= 1.5
                    factors.append(
                        f"Domain is very new ({age:.1f} years old), which can be a risk factor."
                    )
                else:
                    factors.append(f"Domain is relatively new ({age:.1f} years old).")
        except Exception:
            factors.append("Could not determine domain age.")
        # 3. Google Safe Browsing Check

        safe_browsing_result = await check_google_safe_browsing(url)
        if safe_browsing_result and safe_browsing_result.get("matches"):
            score -= 4.0
            factors.append(
                "URL is flagged by Google Safe Browsing as potentially malicious."
            )
        else:
            score += 1.0
            factors.append("URL is not flagged by Google Safe Browsing.")
        # 4. Content Analysis

        async with httpx.AsyncClient() as client:
            response = await client.get(url, follow_redirects=True)
            soup = BeautifulSoup(response.text, "html.parser")

            # Social media presence

            social_links = [
                a["href"]
                for a in soup.find_all("a", href=True)
                if any(
                    social in a["href"]
                    for social in ["twitter.com", "facebook.com", "linkedin.com"]
                )
            ]
            if social_links:
                score += 0.5
                factors.append("Social media presence detected.")
            # Clickbait phrases

            clickbait_phrases = ["you won't believe", "shocking", "secret", "revealed"]
            text_content = soup.get_text().lower()
            if any(phrase in text_content for phrase in clickbait_phrases):
                score -= 1.0
                factors.append("Clickbait phrases found in content.")
            # Ad count

            if len(soup.find_all("iframe")) > 5:
                score -= 1.0
                factors.append("Excessive number of ads detected.")
        final_score = max(0.0, min(10.0, score))

        return CredibilityResult(
            url=url,
            credibility_score=round(final_score, 2),
            factors=factors,
        )
    except Exception as e:
        logger.error(f"Error assessing credibility for URL '{url}': {e}")
        return CredibilityResult(
            url=url,
            credibility_score=0.0,
            factors=[],
            error=f"An error occurred: {e}",
        )


# --- CLI Integration ---

app = typer.Typer(
    name="credibility",
    help="Assesses the credibility of a web source.",
    no_args_is_help=True,
)


@app.command("assess")
def run_credibility_assessment_cli(
    url: str = typer.Argument(..., help="The URL to assess."),
):
    """
    Assesses the credibility of a web source.
    """
    console = Console()

    async def assess():
        return await assess_source_credibility(url)

    result = asyncio.run(assess())

    if result.error:
        console.print(f"[bold red]Error:[/] {result.error}")
        return
    score_color = (
        "green"
        if result.credibility_score > 7
        else "yellow" if result.credibility_score > 4 else "red"
    )

    panel = Panel(
        f"[bold {score_color}]Credibility Score: {result.credibility_score}/10.0[/bold {score_color}]\n\n"
        "[bold cyan]Factors considered:[/bold cyan]\n"
        + "\n".join(f"- {factor}" for factor in result.factors),
        title=f"Credibility Assessment for {url}",
        border_style="blue",
    )
    console.print(panel)
