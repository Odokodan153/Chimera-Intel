import typer
import os
import requests
import yfinance as yf
from bs4 import BeautifulSoup
from rich.panel import Panel
from .utils import console, save_or_print_results

def get_financials_yfinance(ticker_symbol: str) -> dict:
    """Retrieves key financial data for a public company from Yahoo Finance.

    Args:
        ticker_symbol (str): The stock market ticker symbol (e.g., 'AAPL').

    Returns:
        dict: A dictionary of key financial metrics, or an error message.
    """
    try:
        ticker = yf.Ticker(ticker_symbol)
        info = ticker.info
        financials = {
            "companyName": info.get("longName"),
            "sector": info.get("sector"),
            "marketCap": info.get("marketCap"),
            "trailingPE": info.get("trailingPE"),
            "forwardPE": info.get("forwardPE"),
            "dividendYield": info.get("dividendYield"),
            "fiftyTwoWeekHigh": info.get("fiftyTwoWeekHigh"),
            "fiftyTwoWeekLow": info.get("fiftyTwoWeekLow"),
        }
        return financials
    except Exception as e:
        return {"error": f"Could not fetch data for ticker '{ticker_symbol}'. Error: {e}"}

def get_news_gnews(query: str, api_key: str) -> dict:
    """Retrieves news articles from the GNews API.

    Args:
        query (str): The search term (e.g., company name).
        api_key (str): The GNews API key.

    Returns:
        dict: The API response containing news articles, or an error message.
    """
    if not api_key:
        return {"error": "GNews API key not found."}
    
    url = f"[https://gnews.io/api/v4/search?q=](https://gnews.io/api/v4/search?q=)\"{query}\"&lang=en&max=10&token={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": f"An unexpected error occurred with GNews: {e}"}

def scrape_google_patents(query: str, num_patents: int = 5) -> dict:
    """Scrapes the first few patent results from Google Patents.

    Args:
        query (str): The search term (e.g., company name).
        num_patents (int): The maximum number of patents to return.

    Returns:
        dict: A dictionary containing a list of patent titles and links, or an error.
    """
    headers = {"User-Agent": "Mozilla/5.0"}
    url = f"[https://patents.google.com/?q=](https://patents.google.com/?q=)({query})&num=10"
    patents = []
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for result in soup.select('article.search-result', limit=num_patents):
            title_tag = result.select_one('h4.title')
            link_tag = result.select_one('a.abs-url')
            if title_tag and link_tag:
                patents.append({
                    "title": title_tag.text.strip(),
                    "link": "[https://patents.google.com](https://patents.google.com)" + link_tag['href']
                })
        return {"patents": patents}
    except Exception as e:
        return {"error": f"Failed to scrape Google Patents: {e}"}


business_app = typer.Typer()

@business_app.command("run")
def run_business_intel(
    company_name: str = typer.Argument(..., help="The full name of the target company for news/patents."),
    ticker: str = typer.Option(None, help="The stock market ticker for financial data (e.g., AAPL for Apple)."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save the results to a JSON file.")
):
    """Gathers business intelligence: financials, news, and patents."""
    console.print(Panel(f"[bold blue]Starting Business Intelligence Scan for {company_name}[/bold blue]", title="Chimera Intel | Business", border_style="blue"))
    
    gnews_key = os.getenv("GNEWS_API_KEY")
    results = {"company": company_name}

    if ticker:
        console.print(f" [cyan]>[/cyan] Fetching financial data for ticker: {ticker}...")
        results["financials"] = get_financials_yfinance(ticker)
    
    console.print(f" [cyan]>[/cyan] Fetching latest news...")
    results["news"] = get_news_gnews(company_name, gnews_key)

    console.print(f" [cyan]>[/cyan] Scraping Google for patents...")
    results["patents"] = scrape_google_patents(company_name)

    console.print("\n[bold green]Business Intelligence Scan Complete![/bold green]")
    save_or_print_results(results, output_file)