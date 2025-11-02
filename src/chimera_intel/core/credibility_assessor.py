import logging
import asyncio
from typing import Optional
from .schemas import CredibilityResult
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup
import whois
from typing import Optional, Dict, Any
from datetime import datetime
import typer
from .schemas import CredibilityResult, DataVerificationResult, CRAAPScore, BaseResult
from rich.console import Console
from rich.panel import Panel
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)


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
            error=None,  # ADDED: Explicitly set error to None for success path to resolve mypy error
        )
    except Exception as e:
        logger.error(f"Error assessing credibility for URL '{url}': {e}")
        return CredibilityResult(
            url=url,
            credibility_score=0.0,
            factors=[],
            error=f"An error occurred: {e}",
        )
async def assess_data_reliability(
    source_identifier: str,
    data: Dict[str, Any],
    timestamp: Optional[datetime] = None,
) -> DataVerificationResult:
    """
    Implements a CRAAP-like model to assign a Source Reliability Score.
    
    This is a simplified example. A real implementation would involve
    much more complex logic, ML models, and source reputation databases.
    """
    try:
        scores = {}
        
        # 1. Currency
        data_age_days = 30 # Default age if no timestamp
        if timestamp:
            # Ensure timestamp is offset-aware for comparison
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=datetime.now().astimezone().tzinfo)
            data_age_days = (datetime.now(timestamp.tzinfo) - timestamp).days
        
        if data_age_days < 7:
            scores["currency"] = 5.0
        elif data_age_days < 30:
            scores["currency"] = 4.0
        elif data_age_days < 180:
            scores["currency"] = 2.5
        else:
            scores["currency"] = 1.0

        # 2. Authority (Example logic)
        # In a real app, you'd check this against a trusted source list.
        trusted_sources = ["otx.alienvault.com", "vulners.com", "nvd.nist.gov", "hibp.com"]
        if any(trusted in source_identifier for trusted in trusted_sources):
            scores["authority"] = 5.0
        elif "local scan" in source_identifier.lower() or "nmap" in source_identifier.lower():
            scores["authority"] = 4.0 # Data from our own tools
        elif "google.com" in source_identifier.lower() or "gnews" in source_identifier.lower():
            scores["authority"] = 3.0 # General search
        else:
            scores["authority"] = 2.0 # Unknown

        # 3. Accuracy (Example logic)
        # Check for completeness and errors
        if data.get("error"):
            scores["accuracy"] = 1.0
        elif len(data.keys()) > 5: # More fields = more complete
            scores["accuracy"] = 4.5
        elif len(data.keys()) > 2:
            scores["accuracy"] = 3.5
        else:
            scores["accuracy"] = 2.0
        
        # 4. Relevance & Purpose (Mocked for this example)
        scores["relevance"] = 4.0 # Assumed to be relevant if it was collected
        scores["purpose"] = 4.0 # Assumed to be objective unless proven otherwise
        
        craap = CRAAPScore(
            currency=scores["currency"],
            relevance=scores["relevance"],
            authority=scores["authority"],
            accuracy=scores["accuracy"],
            purpose=scores["purpose"],
            overall_score=sum(scores.values()) / 5.0
        )
        
        # Convert 0-5 scale to 0-100
        reliability_score = craap.overall_score * 20 

        return DataVerificationResult(
            source_identifier=source_identifier,
            reliability_score=round(reliability_score, 2),
            craap_assessment=craap,
            error=None
        )

    except Exception as e:
        logger.error(f"Error during data verification for '{source_identifier}': {e}", exc_info=True)
        return DataVerificationResult(
            source_identifier=source_identifier,
            reliability_score=0.0,
            error=str(e)
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
