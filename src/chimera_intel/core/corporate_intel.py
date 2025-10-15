"""
Module for gathering deep corporate and strategic intelligence.

This module provides functions for analyzing a company's hiring trends,
employee sentiment, supply chain, intellectual property, and regulatory activities.
"""

import typer
import logging
from bs4 import BeautifulSoup
from typing import List, Dict, Optional, Any
from sec_api import QueryApi, ExtractorApi  # type: ignore
from .schemas import (
    HiringTrendsResult,
    EmployeeSentimentResult,
    TradeDataResult,
    TrademarkResult,
    LobbyingResult,
    SECFilingAnalysis,
    JobPosting,
    Shipment,
    Trademark,
    LobbyingRecord,
)
from .utils import save_or_print_results, is_valid_domain, console
from .database import save_scan_to_db
from .http_client import sync_client
from .config_loader import API_KEYS
from .project_manager import get_active_project

logger = logging.getLogger(__name__)

# --- Human Capital Intelligence ---


def get_hiring_trends(domain: str) -> HiringTrendsResult:
    """
    Analyzes a company's hiring trends by scraping its careers page.
    NOTE: This is a best-effort generic scraper and may not work for all sites.
    """
    logger.info(f"Analyzing hiring trends for {domain}")

    if not is_valid_domain(domain):
        return HiringTrendsResult(total_postings=0, error="Invalid domain provided.")
    urls_to_try = [f"https://www.{domain}/careers", f"https://www.{domain}/jobs"]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    postings: List[JobPosting] = []
    trends: Dict[str, int] = {}

    for url in urls_to_try:
        try:
            response = sync_client.get(url, headers=headers, follow_redirects=True)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                job_links = soup.find_all("a", href=True)
                for link in job_links:
                    text = link.text.strip()
                    if any(
                        kw in text.lower()
                        for kw in [
                            "engineer",
                            "manager",
                            "developer",
                            "analyst",
                            "scientist",
                            "sales",
                        ]
                    ):
                        postings.append(JobPosting(title=text))
                if postings:
                    for post in postings:
                        if (
                            "engineer" in post.title.lower()
                            or "developer" in post.title.lower()
                        ):
                            trends["Engineering"] = trends.get("Engineering", 0) + 1
                        elif (
                            "sales" in post.title.lower()
                            or "marketing" in post.title.lower()
                        ):
                            trends["Sales/Marketing"] = (
                                trends.get("Sales/Marketing", 0) + 1
                            )
                        elif (
                            "data" in post.title.lower()
                            or "analyst" in post.title.lower()
                        ):
                            trends["Data/Analytics"] = (
                                trends.get("Data/Analytics", 0) + 1
                            )
                    # Create a unique list of job postings

                    unique_postings = {p.title: p for p in postings}.values()
                    return HiringTrendsResult(
                        total_postings=len(postings),
                        trends_by_department=trends,
                        job_postings=list(unique_postings),
                    )
        except Exception as e:
            logger.warning(f"Could not scrape hiring trends from {url}: {e}")
            continue
    return HiringTrendsResult(
        total_postings=0,
        job_postings=[],
        error="Could not find or parse a careers page.",
    )


def get_employee_sentiment(company_name: str) -> EmployeeSentimentResult:
    """
    Analyzes employee sentiment using the Aura Intelligence API.
    """
    api_key = API_KEYS.aura_api_key
    if not api_key:
        return EmployeeSentimentResult(
            error="Aura Intelligence API key not found in .env file."
        )
    logger.info(f"Fetching employee sentiment for '{company_name}' from Aura API.")
    base_url = "https://api.getaura.ai/v1/sentiments"
    params = {"company": company_name}
    headers = {"Authorization": f"Bearer {api_key}"}

    try:
        response = sync_client.get(base_url, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()

        return EmployeeSentimentResult(
            overall_rating=data.get("overall_rating"),
            ceo_approval=f"{data.get('ceo_approval_percentage', 0)}%",
            sentiment_summary=data.get("sentiment_by_category", {}),
        )
    except Exception as e:
        logger.error(f"Failed to get employee sentiment for {company_name}: {e}")
        return EmployeeSentimentResult(
            error=f"An error occurred with the Aura API: {e}"
        )


# --- Supply Chain Intelligence ---


def get_trade_data(company_name: str) -> TradeDataResult:
    """
    Retrieves import/export records from the ImportGenius API.
    """
    api_key = API_KEYS.import_genius_api_key
    if not api_key:
        return TradeDataResult(
            total_shipments=0, error="ImportGenius API key not found in .env file."
        )
    logger.info(f"Retrieving trade data for {company_name} from ImportGenius.")
    base_url = "https://api.importgenius.com/v2/shipments/search"
    params = {"q": company_name, "api_key": api_key}

    try:
        response = sync_client.get(base_url, params=params)
        response.raise_for_status()
        data = response.json()

        shipments = [
            Shipment(
                date=shipment.get("arrival_date"),
                shipper=shipment.get("shipper", {}).get("name"),
                consignee=shipment.get("consignee", {}).get("name"),
                product_description=shipment.get("description"),
                weight_kg=shipment.get("weight_kg"),
            )
            for shipment in data.get("shipments", [])
        ]

        return TradeDataResult(
            total_shipments=data.get("total_results", 0),
            shipments=shipments,
        )
    except Exception as e:
        logger.error(f"Failed to get trade data for {company_name}: {e}")
        return TradeDataResult(
            total_shipments=0, error=f"An error occurred with the ImportGenius API: {e}"
        )


# --- Deeper IP Intelligence ---


def get_trademarks(company_name: str) -> TrademarkResult:
    """
    Searches for trademarks filed by a company using the USPTO Trademark API via RapidAPI.
    """
    api_key = API_KEYS.uspto_api_key
    if not api_key:
        return TrademarkResult(
            total_found=0, error="USPTO Trademark API key not found in .env file."
        )
    logger.info(f"Searching for trademarks for owner: {company_name}")

    url = f"https://uspto-trademark.p.rapidapi.com/v1/ownerSearch/{company_name.replace(' ', '%20')}"
    headers = {
        "X-RapidAPI-Key": api_key,
        "X-RapidAPI-Host": "uspto-trademark.p.rapidapi.com",
    }

    try:
        response = sync_client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        trademarks = [
            Trademark(
                serial_number=item.get("serial_number", "N/A"),
                status=item.get("status_label", "N/A"),
                description=item.get("description", "N/A"),
                owner=item.get("owner", {}).get("name", company_name),
            )
            for item in data
        ]

        return TrademarkResult(total_found=len(trademarks), trademarks=trademarks)
    except Exception as e:
        logger.error(f"Failed to get trademarks for {company_name}: {e}")
        return TrademarkResult(
            total_found=0, error=f"An error occurred with the USPTO Trademark API: {e}"
        )


# --- Regulatory Intelligence ---


def get_lobbying_data(company_name: str) -> LobbyingResult:
    """
    Searches for a company's lobbying activities.
    """
    api_key = API_KEYS.lobbying_data_api_key
    if not api_key:
        return LobbyingResult(
            total_spent=0, error="Lobbying data API key not found in .env file."
        )
    logger.info(f"Analyzing lobbying data for {company_name}.")
    base_url = "https://api.propublica.org/congress/v1/lobbying/search.json"
    params = {"query": company_name}
    headers = {"X-API-Key": api_key}

    try:
        response = sync_client.get(base_url, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()

        records = [
            LobbyingRecord(
                issue=record.get("specific_issue"),
                amount=int(float(record.get("amount", 0))),
                year=int(record.get("year", 0)),
            )
            for record in data.get("results", [{}])[0].get("lobbying_represents", [])
        ]

        total_spent = sum(r.amount for r in records)

        return LobbyingResult(total_spent=total_spent, records=records)
    except Exception as e:
        logger.error(f"Failed to get lobbying data for {company_name}: {e}")
        return LobbyingResult(
            total_spent=0, error=f"An error occurred with the LobbyingData.com API: {e}"
        )


def get_sec_filings_analysis(ticker: str) -> Optional[SECFilingAnalysis]:
    """
    Finds the latest 10-K filing for a ticker and extracts the 'Risk Factors' section.
    NOTE: This remains synchronous as the sec-api library does not support async.

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
        queryApi = QueryApi(api_key=api_key)
        query: Dict[str, Any] = {
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

        extractorApi = ExtractorApi(api_key=api_key)
        risk_factors_text = extractorApi.get_section(
            filing_url=latest_filing_url,
            section="1A",
            return_type="text",
        )

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


corporate_intel_app = typer.Typer()


@corporate_intel_app.command("hr-intel")
def run_hr_intel(
    target: Optional[str] = typer.Argument(
        None, help="The company domain or name. Uses active project if not provided."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes human capital: hiring trends and employee sentiment."""
    target_name = target
    target_domain = None
    target_company = None

    if not target_name:
        active_project = get_active_project()
        if active_project:
            target_domain = active_project.domain
            target_company = active_project.company_name
            target_name = target_company or target_domain
            console.print(
                f"[bold cyan]Using target '{target_name}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No target provided and no active project set."
            )
            raise typer.Exit(code=1)
    else:
        if is_valid_domain(target_name):
            target_domain = target_name
            target_company = target_name.split(".")[0]  # Best effort
        else:
            target_company = target_name
    if not target_name:
        console.print(
            "[bold red]Error:[/bold red] A target name or domain is required."
        )
        raise typer.Exit(code=1)
    hiring_results = (
        get_hiring_trends(target_domain)
        if target_domain
        else HiringTrendsResult(
            total_postings=0, error="Domain needed for hiring trends."
        )
    )
    sentiment_results = (
        get_employee_sentiment(target_company)
        if target_company
        else EmployeeSentimentResult(
            error="Company name needed for sentiment analysis."
        )
    )

    results = {
        "hiring_trends": hiring_results.model_dump(),
        "employee_sentiment": sentiment_results.model_dump(),
    }

    save_or_print_results(results, output_file)
    save_scan_to_db(target=target_name, module="corporate_hr_intel", data=results)


@corporate_intel_app.command("supplychain")
def run_supplychain_intel(
    company_name: Optional[str] = typer.Argument(
        None, help="The legal name of the company. Uses active project if not provided."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Investigates a company's supply chain via trade data."""
    target_company = company_name
    if not target_company:
        active_project = get_active_project()
        if active_project and active_project.company_name:
            target_company = active_project.company_name
            console.print(
                f"[bold cyan]Using company name '{target_company}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No company name provided and no active project with a company name is set."
            )
            raise typer.Exit(code=1)
    if not target_company:
        console.print("[bold red]Error:[/bold red] A company name is required.")
        raise typer.Exit(code=1)
    trade_data = get_trade_data(target_company)
    results = trade_data.model_dump()
    save_or_print_results(results, output_file)
    save_scan_to_db(target=target_company, module="corporate_supplychain", data=results)


@corporate_intel_app.command("ip-deep")
def run_ip_intel(
    company_name: Optional[str] = typer.Argument(
        None, help="The legal name of the company. Uses active project if not provided."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Performs deep intellectual property analysis (trademarks)."""
    target_company = company_name
    if not target_company:
        active_project = get_active_project()
        if active_project and active_project.company_name:
            target_company = active_project.company_name
            console.print(
                f"[bold cyan]Using company name '{target_company}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No company name provided and no active project with a company name is set."
            )
            raise typer.Exit(code=1)
    if not target_company:
        console.print("[bold red]Error:[/bold red] A company name is required.")
        raise typer.Exit(code=1)
    trademark_data = get_trademarks(target_company)
    results = trademark_data.model_dump()
    save_or_print_results(results, output_file)
    save_scan_to_db(target=target_company, module="corporate_ip_deep", data=results)


@corporate_intel_app.command("regulatory")
def run_regulatory_intel(
    company_name: Optional[str] = typer.Argument(
        None, help="The legal name of the company. Uses active project if not provided."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes regulatory and lobbying activities."""
    target_company = company_name
    if not target_company:
        active_project = get_active_project()
        if active_project and active_project.company_name:
            target_company = active_project.company_name
            console.print(
                f"[bold cyan]Using company name '{target_company}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No company name provided and no active project with a company name is set."
            )
            raise typer.Exit(code=1)
    if not target_company:
        console.print("[bold red]Error:[/bold red] A company name is required.")
        raise typer.Exit(code=1)
    lobbying_data = get_lobbying_data(target_company)
    results = lobbying_data.model_dump()
    save_or_print_results(results, output_file)
    save_scan_to_db(target=target_company, module="corporate_regulatory", data=results)


@corporate_intel_app.command("sec-filings")
def run_sec_filings_intel(
    ticker: Optional[str] = typer.Argument(
        None,
        help="The stock ticker of the company. Uses active project if not provided.",
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Analyzes a company's SEC filings for risk factors."""
    target_ticker = ticker
    if not target_ticker:
        active_project = get_active_project()
        if active_project and active_project.ticker:
            target_ticker = active_project.ticker
            console.print(
                f"[bold cyan]Using ticker '{target_ticker}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No ticker provided and no active project with a ticker is set."
            )
            raise typer.Exit(code=1)
    if not target_ticker:
        console.print("[bold red]Error:[/bold red] A stock ticker is required.")
        raise typer.Exit(code=1)
    filings_data = get_sec_filings_analysis(target_ticker)
    if filings_data:
        results = filings_data.model_dump()
        save_or_print_results(results, output_file)
        save_scan_to_db(
            target=target_ticker, module="corporate_sec_filings", data=results
        )
