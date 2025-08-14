import typer
import yfinance as yf
from bs4 import BeautifulSoup
from rich.panel import Panel

# --- CORRECTED Absolute Imports ---
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import API_KEYS
# --- CHANGE: Import the centralized synchronous client ---
from chimera_intel.core.http_client import sync_client 

def get_financials_yfinance(ticker_symbol: str) -> dict:
    """
    Retrieves key financial data for a public company from Yahoo Finance.
    (Note: yfinance uses its own internal http client, so this function is not refactored.)

    Args:
        ticker_symbol (str): The stock market ticker symbol (e.g., 'AAPL').

    Returns:
        dict: A dictionary of key financial metrics, or an error message.
    """
    try:
        ticker = yf.Ticker(ticker_symbol)
        info = ticker.info
        # We select a few key metrics for a concise report.
        financials = {
            "companyName": info.get("longName"),
            "sector": info.get("sector"),
            "marketCap": info.get("marketCap"),
            "trailingPE": info.get("trailingPE"),
            "forwardPE": info.get("forwardPE"),
            "dividendYield": info.get("dividendYield"),
        }
        return financials
    except Exception as e:
        return {"error": f"Could not fetch data for ticker '{ticker_symbol}'. It may be invalid. Error: {e}"}

def get_news_gnews(query: str, api_key: str) -> dict:
    """
    Retrieves news articles from the GNews API using the resilient central client.

    Args:
        query (str): The search term (e.g., company name).
        api_key (str): The GNews API key.

    Returns:
        dict: The API response containing news articles, or an error message.
    """
    if not api_key:
        return {"error": "GNews API key not found."}
    
    url = f"https://gnews.io/api/v4/search?q=\"{query}\"&lang=en&max=10&token={api_key}"
    try:
        # --- CHANGE: Use the global sync_client which has timeouts and retries built-in ---
        response = sync_client.get(url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": f"An unexpected error occurred with GNews: {e}"}

def scrape_google_patents(query: str, num_patents: int = 5) -> dict:
    """
    Scrapes the first few patent results from Google Patents using the resilient central client.

    Args:
        query (str): The search term (e.g., company name).
        num_patents (int): The maximum number of patents to return.

    Returns:
        dict: A dictionary containing a list of patent titles and links, or an error.
    """
    headers = {"User-Agent": "Mozilla/5.0"} # Scrapers often need a user-agent
    url = f"https://patents.google.com/?q=({query})&num=10"
    patents = []
    try:
        # --- CHANGE: Use the global sync_client for the scraping request ---
        response = sync_client.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
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


# --- Typer CLI Application ---

business_app = typer.Typer()

@business_app.command("run")
def run_business_intel(
    company_name: str = typer.Argument(..., help="The full name of the target company for news/patents."),
    ticker: str = typer.Option(None, help="The stock market ticker for financial data (e.g., AAPL for Apple)."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save the results to a JSON file.")
):
    """Gathers business intelligence: financials, news, and patents."""
    console.print(Panel(f"[bold blue]Starting Business Intelligence Scan for {company_name}[/bold blue]", title="Chimera Intel | Business", border_style="blue"))
    
    # Get API key from the centralized Pydantic settings object
    gnews_key = API_KEYS.gnews_api_key
    
    # Financials are only fetched if a ticker symbol is provided
    financial_data = get_financials_yfinance(ticker) if ticker else "Not provided"
    
    results = {
        "company": company_name,
        "financials": financial_data,
        "news": get_news_gnews(company_name, gnews_key),
        "patents": scrape_google_patents(company_name)
    }

    console.print("\n[bold green]Business Intelligence Scan Complete![/bold green]")
    save_or_print_results(results, output_file)
    save_scan_to_db(target=company_name, module="business_intel", data=results)