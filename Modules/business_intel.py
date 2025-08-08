import typer
import os
import requests
import json
import yfinance as yf
from bs4 import BeautifulSoup
from rich.console import Console
from rich.json import JSON

console = Console()

# --- Data Gathering Functions for Business Intelligence ---

def get_financials_yfinance(ticker_symbol: str) -> dict:
    """Retrieves key financial data for a public company from Yahoo Finance."""
    try:
        ticker = yf.Ticker(ticker_symbol)
        # Fetch basic info, which is a large dictionary of data
        info = ticker.info
        # Select a few key metrics for a concise report
        financials = {
            "companyName": info.get("longName"),
            "sector": info.get("sector"),
            "industry": info.get("industry"),
            "marketCap": info.get("marketCap"),
            "trailingPE": info.get("trailingPE"),
            "forwardPE": info.get("forwardPE"),
            "dividendYield": info.get("dividendYield"),
            "fiftyTwoWeekHigh": info.get("fiftyTwoWeekHigh"),
            "fiftyTwoWeekLow": info.get("fiftyTwoWeekLow"),
        }
        return financials
    except Exception as e:
        return {"error": f"Could not fetch data for ticker '{ticker_symbol}'. It may be invalid or delisted. Error: {e}"}

def get_news_gnews(query: str, api_key: str) -> dict:
    """Retrieves news articles from the GNews API."""
    if not api_key:
        return {"error": "GNews API key not found."}
    
    url = f"https://gnews.io/api/v4/search?q=\"{query}\"&lang=en&max=10&token={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": f"An unexpected error occurred with GNews: {e}"}

def scrape_google_patents(query: str, num_patents: int = 5) -> dict:
    """Scrapes the first few patent results from Google Patents."""
    headers = {"User-Agent": "Mozilla/5.0"}
    url = f"https://patents.google.com/?q=({query})&num=10"
    patents = []
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Note: Google's HTML can change. This selector is as of Aug 2025.
        for result in soup.select('article.search-result', limit=num_patents):
            title_tag = result.select_one('h4.title')
            link_tag = result.select_one('a.abs-url')
            if title_tag and link_tag:
                patents.append({
                    "title": title_tag.text.strip(),
                    "link": "https://patents.google.com" + link_tag['href']
                })
        return {"patents": patents}
    except Exception as e:
        return {"error": f"Failed to scrape Google Patents: {e}"}


# --- Typer CLI Application for this module ---

business_app = typer.Typer()

@business_app.command("run")
def run_business_intel(
    company_name: str = typer.Argument(..., help="The full name of the target company for news/patents."),
    ticker: str = typer.Option(None, help="The stock market ticker for financial data (e.g., AAPL for Apple).")
):
    """
    Gathers business intelligence: financials, news, and patents.
    """
    console.print(f"\n[bold blue]--- Starting Business Intelligence Scan for {company_name} ---[/bold blue]")
    
    gnews_key = os.getenv("GNEWS_API_KEY")
    results = {"company": company_name}

    # --- Financials (only if ticker is provided) ---
    if ticker:
        console.print(f" [cyan]>[/cyan] Fetching financial data for ticker: {ticker}...")
        results["financials"] = get_financials_yfinance(ticker)
    
    # --- News ---
    console.print(f" [cyan]>[/cyan] Fetching latest news...")
    results["news"] = get_news_gnews(company_name, gnews_key)

    # --- Patents ---
    console.print(f" [cyan]>[/cyan] Scraping Google for patents...")
    results["patents"] = scrape_google_patents(company_name)

    # --- Print Results ---
    json_str = json.dumps(results, indent=4, ensure_ascii=False, default=str)
    console.print(JSON(json_str))