import typer
import requests
import yfinance as yf
from bs4 import BeautifulSoup
from rich.panel import Panel
from .utils import console, save_or_print_results
from .database import save_scan_to_db
from .config_loader import API_KEYS # Import the centralized keys

def get_financials_yfinance(ticker_symbol: str) -> dict:
    """
    Retrieves key financial data for a public company from Yahoo Finance.

    Args:
        ticker_symbol (str): The stock market ticker symbol (e.g., 'AAPL').

    Returns:
        dict: A dictionary of key financial metrics, or an error message.
    """
    try:
        ticker = yf.Ticker(ticker_symbol)
        # .info provides a large dictionary of company data
        info = ticker.info
        # We select a few key metrics for a concise report.
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
        return {"error": f"Could not fetch data for ticker '{ticker_symbol}'. It may be invalid or delisted. Error: {e}"}

def get_news_gnews(query: str, api_key: str) -> dict:
    """
    Retrieves news articles from the GNews API.

    Args:
        query (str): The search term (e.g., company name).
        api_key (str): The GNews API key.

    Returns:
        dict: The API response containing news articles, or an error message.
    """
    if not api_key:
        return {"error": "GNews API key not found. Check your .env file."}
    
    # The query is wrapped in quotes to search for the exact phrase
    url = f"https://gnews.io/api/v4/search?q=\"{query}\"&lang=en&max=10&token={api_key}"
    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"GNews API returned an HTTP error: {e.response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"A network error occurred with GNews: {e}"}

def scrape_google_patents(query: str, num_patents: int = 5) -> dict:
    """
    Scrapes the first few patent results from Google Patents.

    Args:
        query (str): The search term (e.g., company name).
        num_patents (int): The maximum number of patents to return.

    Returns:
        dict: A dictionary containing a list of patent titles and links, or an error.
    """
    # Use a common user-agent to avoid being blocked
    headers = {"User-Agent": "Mozilla/5.0"}
    url = f"https://patents.google.com/?q=({query})&num=10"
    patents = []
    try:
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        # Use BeautifulSoup to parse the HTML content of the page
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # NOTE: Selectors can change if Google updates their website structure.
        # This selector is specific to the layout as of the time of writing.
        for result in soup.select('article.search-result', limit=num_patents):
            title_tag = result.select_one('h4.title')
            link_tag = result.select_one('a.abs-url')
            if title_tag and link_tag:
                patents.append({
                    "title": title_tag.text.strip(),
                    "link": "https://patents.google.com" + link_tag['href']
                })
            else:
                # This helps debug if Google changes its HTML structure
                console.print("[bold yellow]Warning:[/] Could not parse a patent result, HTML structure may have changed.")

        return {"patents": patents}
    except requests.exceptions.RequestException as e:
        return {"error": f"Failed to scrape Google Patents due to a network error: {e}"}
    except Exception as e:
        # Catch other potential errors, e.g., during soup parsing
        return {"error": f"An unexpected error occurred while scraping Google Patents: {e}"}


business_app = typer.Typer()

@business_app.command("run")
def run_business_intel(
    company_name: str = typer.Argument(..., help="The full name of the target company for news/patents."),
    ticker: str = typer.Option(None, help="The stock market ticker for financial data (e.g., AAPL for Apple)."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save the results to a JSON file.")
):
    """Gathers business intelligence: financials, news, and patents."""
    console.print(Panel(f"[bold blue]Starting Business Intelligence Scan for {company_name}[/bold blue]", title="Chimera Intel | Business", border_style="blue"))
    
    # IMPROVEMENT: Get key from the centralized API_KEYS dictionary
    gnews_key = API_KEYS.get("gnews")
    
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