"""
Business intelligence module for gathering financial data, news, and patents.

This module provides functions to collect business-related intelligence on a target
company. It uses the 'yfinance' library for financial metrics, the GNews API for
news articles, and scrapes Google Patents for recent filings. All network requests
are routed through the centralized HTTP client for consistency and resilience.
"""

import typer
import yfinance as yf  # type: ignore
from bs4 import BeautifulSoup
from httpx import RequestError, HTTPStatusError
import logging
from sec_api import QueryApi, ExtractorApi
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.http_client import sync_client
from typing import Optional
from chimera_intel.core.schemas import (
    Financials,
    GNewsResult,
    Patent,
    PatentResult,
    BusinessIntelData,
    BusinessIntelResult,
    SECFilingAnalysis,
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
        if not info or info.get("trailingPE") is None:
            raise ValueError("Incomplete data received from yfinance API.")
        return Financials(
            companyName=info.get("longName"),
            sector=info.get("sector"),
            marketCap=info.get("marketCap"),
            trailingPE=info.get("trailingPE"),
            forwardPE=info.get("forwardPE"),
            dividendYield=info.get("dividendYield"),
        )
    except (ValueError, KeyError) as e:
        logger.warning(
            "Could not fetch or parse data for ticker '%s': %s", ticker_symbol, e
        )
        return Financials(
            error=f"Could not fetch data for ticker '{ticker_symbol}'. It may be invalid or delisted."
        )
    except Exception as e:
        logger.critical(
            "An unexpected error occurred in get_financials_yfinance for ticker '%s': %s",
            ticker_symbol,
            e,
        )
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
    url = f'https://gnews.io/api/v4/search?q="{query}"&lang=en&max=10&token={api_key}'
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
        logger.critical(
            "An unexpected error occurred in get_news_gnews for query '%s': %s",
            query,
            e,
        )
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
        soup = BeautifulSoup(response.text, "html.parser")

        patents_list: list[Patent] = []
        for result in soup.select("article.search-result", limit=num_patents):
            title_tag = result.select_one("h4.title")
            link_tag = result.select_one("a.abs-url")

            if title_tag and link_tag:
                href = link_tag.get("href")
                if isinstance(href, str):
                    patents_list.append(
                        Patent(
                            title=title_tag.text.strip(),
                            link="https://patents.google.com" + href,
                        )
                    )
        return PatentResult(patents=patents_list)
    except HTTPStatusError as e:
        logger.error("HTTP error scraping patents for query '%s': %s", query, e)
        return PatentResult(
            error=f"HTTP error scraping patents: {e.response.status_code}"
        )
    except RequestError as e:
        logger.error("Network error scraping patents for query '%s': %s", query, e)
        return PatentResult(error=f"Network error scraping patents: {e}")
    except Exception as e:
        logger.critical(
            "An unexpected error occurred while scraping patents for query '%s': %s",
            query,
            e,
        )
        return PatentResult(
            error=f"An unexpected error occurred while scraping patents: {e}"
        )


def get_sec_filings_analysis(ticker: str) -> Optional[SECFilingAnalysis]:
    """
    Finds the latest 10-K filing for a ticker and extracts the 'Risk Factors' section.

    Args:
        ticker (str): The stock market ticker symbol.

    Returns:
        Optional[SECFilingAnalysis]: A Pydantic model with the analysis, or None.
    """
    api_key = API_KEYS.sec_api_io_key
    if not api_key:
        logger.warning("sec-api.io key not found. Skipping SEC filings analysis.")
        return None
    try:
        # Step 1: Find the latest 10-K filing to get its URL

        queryApi = QueryApi(api_key=api_key)
        query = {
            "query": f'ticker:{ticker} AND formType:"10-K"',
            "from": "0",
            "size": "1",
            "sort": [{"filedAt": {"order": "desc"}}],
        }
        filings = queryApi.get_filings(query)

        if not filings.get("filings"):
            logger.warning("No 10-K filings found for ticker '%s'.", ticker)
            return None
        latest_filing_url = filings["filings"][0]["linkToFilingDetails"]

        # Step 2: Use the Extractor API to get the 'Risk Factors' section (Item 1A)

        extractorApi = ExtractorApi(api_key=api_key)
        risk_factors_text = extractorApi.get_section(
            filing_url=latest_filing_url,
            section="1A",  # Item 1A is "Risk Factors"
            return_type="text",
        )

        # Basic summary (can be enhanced with AI later)

        summary = (
            (risk_factors_text[:700] + "...")
            if len(risk_factors_text) > 700
            else risk_factors_text
        )

        return SECFilingAnalysis(
            filing_url=latest_filing_url, risk_factors_summary=summary
        )
    except Exception as e:
        logger.error(
            "An error occurred during SEC filing analysis for ticker '%s': %s",
            ticker,
            e,
        )
        return SECFilingAnalysis(filing_url="", error=str(e))


# --- Typer CLI Application ---


business_app = typer.Typer()


@business_app.command("run")
def run_business_intel(
    company_name: str = typer.Argument(
        ..., help="The full name of the target company."
    ),
    ticker: str = typer.Option(
        None, help="The stock market ticker for financial data."
    ),
    filings: bool = typer.Option(
        False, "--filings", help="Enable SEC filings analysis (requires ticker)."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Gathers business intelligence: financials, news, patents, and SEC filings.

    Args:
        company_name (str): The full name of the target company.
        ticker (str): The stock market ticker for financial data.
        filings (bool): Flag to enable SEC filings analysis.
        output_file (str): Optional path to save the results to a JSON file.
    """
    logger.info(
        "Starting business intelligence scan for %s (Ticker: %s)",
        company_name,
        ticker or "N/A",
    )

    gnews_key = API_KEYS.gnews_api_key
    financial_data = get_financials_yfinance(ticker) if ticker else "Not provided"

    filings_analysis = None
    if filings and ticker:
        with console.status(
            f"[bold cyan]Analyzing SEC filings for {ticker}...[/bold cyan]"
        ):
            filings_analysis = get_sec_filings_analysis(ticker)
    elif filings and not ticker:
        logger.warning("The --filings flag requires a --ticker to be provided.")
    if not gnews_key:
        logger.warning("GNews API key not found. Skipping news gathering.")
        news_data = GNewsResult(error="GNews API key not configured.")
    else:
        news_data = get_news_gnews(company_name, gnews_key)
    intel_data = BusinessIntelData(
        financials=financial_data,
        news=news_data,
        patents=scrape_google_patents(company_name),
        sec_filings_analysis=filings_analysis,
    )

    results_model = BusinessIntelResult(company=company_name, business_intel=intel_data)
    results_dict = results_model.model_dump(exclude_none=True)

    logger.info("Business intelligence scan complete for %s", company_name)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=company_name, module="business_intel", data=results_dict)
