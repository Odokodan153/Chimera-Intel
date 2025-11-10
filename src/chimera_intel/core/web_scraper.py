"""
(NEW) Active Web Scraper Module.

Provides functions to actively scrape and parse web content, including
news articles and dynamic (JavaScript-rendered) web pages.

Implements the data collection part of the "OSINT + HUMINT Fusion Hub".
"""

import typer
from typing import Optional, List
from pathlib import Path
import json
from newspaper import Article
from playwright.sync_api import sync_playwright, Error
from .utils import console
from .schemas import ScrapedArticle

web_scraper_app = typer.Typer(
    name="web-scraper",
    help="Active tools for scraping and parsing web data.",
)

def parse_article_from_url(url: str) -> Optional[ScrapedArticle]:
    """
    Uses 'newspaper3k' to scrape and parse a single news article.
    
    Args:
        url: The URL of the article to parse.
        
    Returns:
        A ScrapedArticle schema object or None if parsing fails.
    """
    try:
        article = Article(url)
        article.download()
        article.parse()
        
        # Extract data into our schema
        scraped_data = ScrapedArticle(
            url=url,
            title=article.title,
            text_content=article.text,
            authors=article.authors,
            publish_date=article.publish_date,
            top_image_url=article.top_image
        )
        return scraped_data
        
    except Exception as e:
        console.print(f"[bold red]Article parsing failed for {url}:[/bold red] {e}")
        return None

def scrape_dynamic_page(
    url: str, 
    wait_for_selector: Optional[str] = None
) -> Optional[str]:
    """
    Uses 'playwright' to scrape a dynamic, JavaScript-rendered page.
    
    Args:
        url: The URL of the dynamic page.
        wait_for_selector: (Optional) A CSS selector to wait for before
                           scraping. Useful for pages that load data.
                           
    Returns:
        The full HTML content of the rendered page or None if fails.
    """
    console.print(f"Launching headless browser to scrape: {url}")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle")
            
            if wait_for_selector:
                console.print(f"Waiting for selector: {wait_for_selector}")
                page.wait_for_selector(wait_for_selector)
                
            content = page.content()
            browser.close()
            return content
            
    except Error as e:
        console.print(f"[bold red]Playwright failed for {url}:[/bold red] {e}")
        return None
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred with Playwright:[/bold red] {e}")
        return None


# --- CLI Commands for this module ---

@web_scraper_app.command("parse-article")
def cli_parse_article(
    url: str = typer.Argument(..., help="The URL of the news article to parse."),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Path to save the extracted data as JSON."
    )
):
    """
    (NEW) Scrapes a single news article and extracts its content.
    """
    with console.status("[bold yellow]Parsing article...[/bold yellow]"):
        article_data = parse_article_from_url(url)
        
    if not article_data:
        console.print("[bold red]Failed to parse article.[/bold red]")
        raise typer.Exit(code=1)
        
    console.print(f"[bold green]Article Parsed Successfully:[/bold green]")
    console.print(f"[bold]Title:[/bold] {article_data.title}")
    console.print(f"[bold]Authors:[/bold] {', '.join(article_data.authors)}")
    console.print(f"[bold]Date:[/bold] {article_data.publish_date}")
    
    if output_file:
        try:
            with output_file.open('w', encoding='utf-8') as f:
                json.dump(article_data.model_dump(mode='json'), f, indent=4)
            console.print(f"Data saved to [cyan]{output_file}[/cyan]")
        except Exception as e:
            console.print(f"[bold red]Failed to save file:[/bold red] {e}")

@web_scraper_app.command("scrape-dynamic")
def cli_scrape_dynamic(
    url: str = typer.Argument(..., help="The URL of the dynamic/JS-rendered page."),
    wait_for: Optional[str] = typer.Option(
        None, "--wait-for",
        help="CSS selector to wait for before saving (e.g., '#profile-card')."
    ),
    output_file: Path = typer.Option(
        ..., "--output", "-o",
        help="Path to save the full rendered HTML."
    )
):
    """
    (NEW) Scrapes a dynamic (JavaScript) page using a headless browser.
    """
    with console.status("[bold yellow]Launching headless browser...[/bold yellow]"):
        html_content = scrape_dynamic_page(url, wait_for_selector=wait_for)
        
    if not html_content:
        console.print("[bold red]Failed to scrape dynamic page.[/bold red]")
        raise typer.Exit(code=1)
        
    try:
        with output_file.open('w', encoding='utf-8') as f:
            f.write(html_content)
        console.print(f"[bold green]Full HTML content saved to [cyan]{output_file}[/cyan][/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to save file:[/bold red] {e}")