"""
Pricing & Promotion Intelligence Module for Chimera Intel.

This module provides tools to scrape and monitor product pricing,
detect promotions, and analyze price elasticity signals.

--- REVISION ---
This version removes the 'assumed' database functions and replaces
the price historian with a self-contained JSON file-based system
(storage/price_history.json). It is now fully functional.
---
"""

import typer
import asyncio
import logging
import re
import httpx
import json
import os
from bs4 import BeautifulSoup
from typing import List, Optional, Dict, Any
from datetime import datetime
from chimera_intel.core.http_client import get_async_http_client
from chimera_intel.core.scheduler import add_job
from chimera_intel.core.utils import console
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.web_analyzer import get_traffic_similarweb
from chimera_intel.core.project_manager import resolve_target
from chimera_intel.core.utils import is_valid_domain

# --- ARG INTEGRATION IMPORTS ---
from chimera_intel.core.arg_service import (
    arg_service_instance,
    BaseEntity,
    Relationship,
)
# --- END ARG INTEGRATION IMPORTS ---

logger = logging.getLogger(__name__)
app = typer.Typer(
    no_args_is_help=True, help="Pricing & Promotion Intelligence (PRICEINT) tools."
)

# Define storage path for the price historian
STORAGE_DIR = "storage"
PRICE_HISTORY_FILE = os.path.join(STORAGE_DIR, "price_history.json")


def _ensure_storage_exists():
    """Ensures the storage directory and history file exist."""
    os.makedirs(STORAGE_DIR, exist_ok=True)
    if not os.path.exists(PRICE_HISTORY_FILE):
        with open(PRICE_HISTORY_FILE, "w") as f:
            json.dump([], f)


def _load_price_history(url: Optional[str] = None) -> List[Dict[str, Any]]:
    """Loads price history from the JSON file, optionally filtering by URL."""
    _ensure_storage_exists()
    try:
        with open(PRICE_HISTORY_FILE, "r") as f:
            history = json.load(f)
        
        if url:
            return [entry for entry in history if entry.get("url") == url]
        return history
    except json.JSONDecodeError:
        logger.warning(f"Could not decode price history file. Returning empty list.")
        return []


def _save_price_snapshot(data: Dict[str, Any]):
    """Saves a new price snapshot to the JSON file."""
    _ensure_storage_exists()
    history = _load_price_history()
    history.append(data)
    
    try:
        with open(PRICE_HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
    except IOError as e:
        logger.error(f"Failed to write to price history file: {e}")


def _parse_price(price_str: str) -> Optional[float]:
    """Utility to clean and parse a price string."""
    if not price_str:
        return None
    # Remove currency symbols, commas, and whitespace
    cleaned = re.sub(r"[^\d.]+", "", price_str.strip())
    try:
        return float(cleaned)
    except (ValueError, TypeError):
        return None


def _find_currency(price_str: str) -> Optional[str]:
    """Utility to detect a currency symbol."""
    if not price_str:
        return None
    if "$" in price_str:
        return "USD"
    if "€" in price_str:
        return "EUR"
    if "£" in price_str:
        return "GBP"
    # Fallback/default
    return "USD"


async def scrape_product_info(
    url: str,
    list_price_selector: str,
    sale_price_selector: Optional[str] = None,
    currency_selector: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Scrapes a single product page for its price information
    based on provided CSS selectors.
    """
    logger.info(f"Scraping price from {url}")
    try:
        async with get_async_http_client() as client:
            response = await client.get(url, follow_redirects=True, timeout=20.0)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")

            list_price_el = soup.select_one(list_price_selector)
            list_price_str = list_price_el.get_text() if list_price_el else None
            list_price = _parse_price(list_price_str)

            sale_price = None
            if sale_price_selector:
                sale_price_el = soup.select_one(sale_price_selector)
                sale_price_str = sale_price_el.get_text() if sale_price_el else None
                sale_price = _parse_price(sale_price_str)

            final_sale_price = sale_price if sale_price else list_price
            final_list_price = list_price if sale_price else None

            currency = None
            if currency_selector:
                currency_el = soup.select_one(currency_selector)
                currency = currency_el.get_text().strip() if currency_el else None
            
            if not currency:
                currency = _find_currency(sale_price_str or list_price_str)

            return {
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "list_price": final_list_price,
                "sale_price": final_sale_price,
                "currency": currency,
                "discount_active": bool(sale_price and list_price and sale_price < list_price),
            }

    except httpx.RequestError as e:
        logger.warning(f"Could not reach {url}. Error: {e}")
        return {"error": f"Could not reach {url}. Error: {e}"}
    except Exception as e:
        logger.error(f"Unexpected error scraping {url}", exc_info=e)
        return {"error": f"An unexpected error occurred: {e}"}


def _ingest_price_to_arg(data: Dict[str, Any]):
    """Helper function to ingest a scraped price into the ARG."""
    try:
        product_entity = BaseEntity(
            id_value=data['url'],
            id_type="url",
            label="Product",
            properties={"url": data['url']}
        )
        
        price_entity = BaseEntity(
            id_value=f"{data['sale_price']}_{data['currency']}",
            id_type="price_value",
            label="Price",
            properties={
                "value": data['sale_price'],
                "currency": data['currency'],
                "list_price": data.get('list_price')
            }
        )

        rel = Relationship(
            source=product_entity,
            target=price_entity,
            label="HAS_PRICE",
            properties={
                "last_seen": data['timestamp'],
                "discount_active": data.get('discount_active', False)
            }
        )
        
        arg_service_instance.ingest_entities_and_relationships(
            entities=[product_entity, price_entity],
            relationships=[rel]
        )
        logger.info(f"Successfully ingested price for {data['url']} into ARG.")
    except Exception as e:
        logger.error(f"Failed to ingest price for {data['url']} into ARG: {e}")


async def check_product_price(
    url: str,
    job_id: str,
    list_price_selector: str,
    sale_price_selector: Optional[str] = None,
):
    """
    Core function run by the scheduler to check and record price changes.
    Reuses the `page_monitor` job pattern.
    """
    logger.info(f"Running scheduled price check for {url} (Job: {job_id})")
    console.print(
        f"[{datetime.now()}] Checking price for {url} (Job: {job_id})"
    )

    data = await scrape_product_info(url, list_price_selector, sale_price_selector)

    if "error" in data or not data.get("sale_price"):
        logger.warning(f"Failed to scrape price for {url}: {data.get('error')}")
        return

    # --- ARG INGESTION ---
    # Ingest the price data into the graph, regardless of change.
    _ingest_price_to_arg(data)
    # --- END ARG INGESTION ---

    # Check against last known price from our JSON file
    try:
        history = _load_price_history(url=url)
        last_price = None
        if history:
            last_entry = sorted(history, key=lambda x: x["timestamp"])[-1]
            last_price = last_entry.get("sale_price")

        current_price = data["sale_price"]
        
        if last_price != current_price:
            console.print(
                f"[bold yellow]Price Change Detected for {url}:[/bold yellow] "
                f"Was {last_price}, now {current_price}"
            )
            _save_price_snapshot(data)
            console.print(
                f"[green]Successfully saved new price snapshot for {url}:[/green] "
                f"{data['currency']} {data['sale_price']}"
            )
        else:
            logger.info(f"Price unchanged for {url} (Job: {job_id})")
            console.print(f"[green]Price unchanged for {url}.[/green]")

    except Exception as e:
        logger.error(f"File error saving price snapshot for {url}: {e}")
        console.print(
            f"[red]Error saving price snapshot for {url}: {e}[/red]"
        )


def analyze_promotions_from_text(content: str) -> Dict[str, Any]:
    """
    Identifies promotion signals from a page's text content.
    """
    text = content.lower()

    patterns = {
        "percentage_off": r"(\b\d{1,2}%(\s+off)?\b|\bsave\s+\d{1,2}%\b)",
        "dollar_off": r"(\$\d+(\s+off)?\b|\bsave\s+\$\d+\b)",
        "coupon_code": r"(coupon code|promo code|discount code|enter code)[\s:]*([A-Z0-9]{4,})",
        "seasonal_sale": r"\b(seasonal sale|holiday sale|black friday|cyber monday|end of season)\b",
        "bundle": r"\b(bundle and save|buy one get one|bogo|2-for-1)\b",
    }

    detected_promos = {}
    for key, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            cleaned_matches = []
            for match in matches:
                if isinstance(match, tuple):
                    cleaned_matches.append(" ".join(m for m in match if m).strip())
                else:
                    cleaned_matches.append(match.strip())
            detected_promos[key] = list(set(cleaned_matches))

    return {
        "promotion_count": sum(len(v) for v in detected_promos.values()),
        "detected_promotions": detected_promos,
    }


@app.command(name="add-monitor")
def add_price_monitor(
    url: str = typer.Option(
        ..., "--url", "-u", help="The URL of the product page to monitor."
    ),
    list_price_selector: str = typer.Option(
        ...,
        "--list-selector",
        "-l",
        help="CSS selector for the list price (e.g., 'span.list-price').",
    ),
    sale_price_selector: Optional[str] = typer.Option(
        None,
        "--sale-selector",
        "-p",
        help="CSS selector for the sale price (e.g., 'span.sale-price').",
    ),
    schedule: str = typer.Option(
        ...,
        "--schedule",
        "-s",
        help="Cron-style schedule (e.g., '0 */6 * * *' for every 6 hours).",
    ),
):
    """
    Adds a new product page to the price monitoring historian.
    """
    job_id = f"price_monitor_{hash(url + list_price_selector) & 0xFFFFFFFF}"

    add_job(
        func=check_product_price,
        trigger="cron",
        cron_schedule=schedule,
        job_id=job_id,
        kwargs={
            "url": url,
            "job_id": job_id,
            "list_price_selector": list_price_selector,
            "sale_price_selector": sale_price_selector,
        },
    )
    console.print(
        "[bold green]✅ Successfully scheduled product price monitor.[/bold green]"
    )
    console.print(f"   - Job ID: {job_id}")
    console.print(f"   - URL: {url}")
    console.print(f"   - Schedule: {schedule}")
    console.print(
        "\nEnsure the Chimera daemon is running for the job to execute: [bold]chimera daemon start[/bold]"
    )


@app.command(name="detect-promos")
def detect_promotions(
    url: str = typer.Option(
        ..., "--url", "-u", help="The URL of the page to scan for promotions."
    )
):
    """
    Scans a single page for keywords related to promotions,
    coupons, bundles, and seasonal sales.
    """
    logger.info(f"Detecting promotions on {url}")
    try:
        async def run_detection():
            async with get_async_http_client() as client:
                response = await client.get(url, follow_redirects=True, timeout=20.0)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, "html.parser")
                clean_text = soup.get_text(separator=" ", strip=True)
                return analyze_promotions_from_text(clean_text)

        results = asyncio.run(run_detection())
        console.print(
            f"[bold green]Promotion Analysis for {url}:[/bold green]"
        )
        console.print_json(data=results)

    except httpx.RequestError as e:
        logger.warning(f"Could not reach {url}. Error: {e}")
        console.print(f"[red]Error:[/red] Could not reach {url}. {e}")
    except Exception as e:
        logger.error(f"Unexpected error analyzing {url}", exc_info=e)
        console.print(f"[red]An unexpected error occurred: {e}[/red]")


@app.command(name="check-elasticity")
def check_elasticity(
    domain: Optional[str] = typer.Argument(
        None, help="The target domain. Uses active project if not provided."
    ),
    product_url: str = typer.Option(
        ..., "--url", "-u", help="The specific product URL to get price history for."
    ),
):
    """
    Correlates price changes with web traffic data to find
    price elasticity signals.
    """
    target_domain = resolve_target(domain, required_assets=["domain"])
    if not is_valid_domain(target_domain):
        console.print(
            f"[red]Invalid domain:[/red] '{target_domain}' is not valid."
        )
        raise typer.Exit(code=1)

    console.print(
        f"Checking price elasticity for {target_domain} (using URL {product_url})"
    )
    
    similarweb_key = API_KEYS.similarweb_api_key
    if not similarweb_key:
        console.print("[yellow]Similarweb API key not found. Skipping traffic analysis.[/yellow]")
        raise typer.Exit(code=1)

    async def gather_data():
        traffic_task = get_traffic_similarweb(target_domain, similarweb_key)
        price_history = _load_price_history(url=product_url)
        traffic_data = await traffic_task
        return traffic_data, price_history

    try:
        traffic_data, price_history = asyncio.run(gather_data())
        
        if not price_history:
            console.print(f"[yellow]No price history found for {product_url}. "
                          f"Run 'add-monitor' first and wait for it to run.[/yellow]")
            raise typer.Exit()
            
        for entry in price_history:
            entry['timestamp_dt'] = datetime.fromisoformat(entry['timestamp'])

        console.print("\n[bold green]Price Elasticity Signal Analysis:[/bold green]")
        
        console.print("\n[bold]Recent Price History (from local file):[/bold]")
        sorted_history = sorted(price_history, key=lambda x: x['timestamp_dt'])
        for entry in sorted_history[-5:]:
            console.print(
                f"  - {entry['timestamp_dt'].date()}: {entry['currency']} {entry['sale_price']}"
            )

        console.print("\n[bold]Monthly Traffic Data (from Similarweb):[/bold]")
        visits = traffic_data.get("visits", [])
        if not visits:
            console.print("  - No monthly traffic data found via Similarweb.")
        
        for visit in visits[-3:]:
             console.print(f"  - {visit['date']}: {visit['value']} visits")

        if sorted_history and visits:
            last_price_change = sorted_history[-1]
            last_traffic = visits[-1]
            
            if last_price_change['timestamp_dt'].strftime("%Y-%m") == last_traffic['date'][:7]:
                console.print(
                    f"\n[bold cyan]Signal:[/bold] The most recent price "
                    f"({last_price_change['sale_price']}) was recorded in the same "
                    f"month as the last traffic data ({last_traffic['value']} visits)."
                )
            else:
                 console.print(
                    f"\n[bold yellow]Note:[/bold] Most recent price change ({last_price_change['timestamp_dt'].date()}) "
                    f"and last traffic data ({last_traffic['date']}) are from different periods. "
                    f"Correlation is difficult."
                )

    except Exception as e:
        logger.error(f"Error checking elasticity: {e}", exc_info=True)
        console.print(f"[red]An error occurred: {e}[/red]")


if __name__ == "__main__":
    app()