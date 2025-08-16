import typer
import yfinance as yf
from bs4 import BeautifulSoup
from httpx import RequestError, HTTPStatusError
import logging

# --- CORRECTED Absolute Imports ---
from chimera_intel.core.utils import save_or_print_results
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.http_client import sync_client
# Import the Pydantic models to ensure type-safe, validated results
from chimera_intel.core.schemas import (
    Financials, GNewsResult, PatentResult, BusinessIntelData, BusinessIntelResult
)
# Get a logger instance for this specific file
logger = logging.getLogger(__name__)


def get_financials_yfinance(ticker_symbol: str) -> Financials:
    """
    Retrieves key financial data for a public company from Yahoo Finance.

    Args:
        ticker_symbol (str): The stock market ticker symbol (e.g., 'AAPL').

    Returns:
        Financials: A Pydantic model containing key financial metrics, or an error message.
    """
    try:
        ticker = yf.Ticker(ticker_symbol)
        info = ticker.info
        if not info or info.get('trailingPE') is None:
             raise ValueError("Incomplete data received from yfinance API.")
             
        return Financials(
            companyName=info.get("longName"),
            sector=info.get("sector"),
            marketCap=info.get("marketCap"),
            trailingPE=info.get("trailingPE"),
            forwardPE=info.get("forwardPE"),
            dividendYield=info.get("dividendYield"),
        )
    # Catch specific, expected errors related to bad data or invalid tickers
    except (ValueError, KeyError) as e:
        logger.warning("Could not fetch or parse data for ticker '%s': %s", ticker_symbol, e)
        return Financials(error=f"Could not fetch data for ticker '{ticker_symbol}'. It may be invalid or delisted.")
    # --- CHANGE: Add a fallback for any other unexpected errors ---
    except Exception as e:
        logger.critical("An unexpected error occurred in get_financials_yfinance for ticker '%s': %s", ticker_symbol, e)
        return Financials(error=f"An unexpected error occurred: {e}")

def get_news_gnews(query: str, api_key: str) -> GNewsResult:
    """
    Retrieves news articles from the GNews API using the resilient central client.

    Args:
        query (str): The search term (e.g., company name).
        api_key (str): The GNews API key.

    Returns:
        GNewsResult: A Pydantic model containing news articles, or an error message.
    """
    if not api_key:
        return GNewsResult(error="GNews API key not found.")
    
    url = f"https://gnews.io/api/v4/search?q=\"{query}\"&lang=en&max=10&token={api_key}"
    try:
        response = sync_client.get(url)
        response.raise_for_status()
        return GNewsResult(**response.json())
    except HTTPStatusError as e:
        logger.error("HTTP error fetching news for query '%s': %s", query, e)
        return GNewsResult(error=f"HTTP error occurred: {e.response.status_code}")
    except RequestError as e:
        logger.error("Network error fetching news for query '%s': %s", query, e)
        return GNewsResult(error=f"A network error occurred: {e}")
    except Exception as e:
        logger.critical("An unexpected error occurred in get_news_gnews for query '%s': %s", query, e)
        return GNewsResult(error=f"An unexpected error occurred: {e}")

def scrape_google_patents(query: str, num_patents: int = 5) -> PatentResult:
    """
    Scrapes the first few patent results from Google Patents using the central client.

    Args:
        query (str): The search term (e.g., company name).
        num_patents (int): The maximum number of patents to return.

    Returns:
        PatentResult: A Pydantic model containing a list of patents, or an error.
    """
    headers = {"User-Agent": "Mozilla/5.0"}
    url = f"https://patents.google.com/?q=({query})&num=10"
    try:
        response = sync_client.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        patents = [
            {"title": title_tag.text.strip(), "link": "https://patents.google.com" + link_tag['href']}
            for result in soup.select('article.search-result', limit=num_patents)
            if (title_tag := result.select_one('h4.title')) and (link_tag := result.select_one('a.abs-url'))
        ]
        return PatentResult(patents=patents)
    except HTTPStatusError as e:
        logger.error("HTTP error scraping patents for query '%s': %s", query, e)
        return PatentResult(error=f"HTTP error scraping patents: {e.response.status_code}")
    except RequestError as e:
        logger.error("Network error scraping patents for query '%s': %s", query, e)
        return PatentResult(error=f"Network error scraping patents: {e}")
    # --- CHANGE: Add a fallback for any other unexpected errors ---
    except Exception as e:
        logger.critical("An unexpected error occurred while scraping patents for query '%s': %s", query, e)
        return PatentResult(error=f"An unexpected error occurred while scraping patents: {e}")


# --- Typer CLI Application ---
business_app = typer.Typer()

@business_app.command("run")
def run_business_intel(
    company_name: str = typer.Argument(..., help="The full name of the target company."),
    ticker: str = typer.Option(None, help="The stock market ticker for financial data."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save the results to a JSON file.")
):
    """
    Gathers business intelligence: financials, news, and patents for a target company.
    """
    logger.info("Starting business intelligence scan for %s (Ticker: %s)", company_name, ticker or "N/A")
    
    gnews_key = API_KEYS.gnews_api_key
    financial_data = get_financials_yfinance(ticker) if ticker else "Not provided"
    
    intel_data = BusinessIntelData(
        financials=financial_data,
        news=get_news_gnews(company_name, gnews_key),
        patents=scrape_google_patents(company_name)
    )

    results_model = BusinessIntelResult(company=company_name, business_intel=intel_data)
    results_dict = results_model.model_dump(exclude_none=True)

    logger.info("Business intelligence scan complete for %s", company_name)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=company_name, module="business_intel", data=results_dict)