"""
Chemical & Materials Intelligence (CHEMINT) Module.

This module is responsible for gathering and analyzing intelligence on chemical
manufacturing, material science breakthroughs, and the supply chains for
specialized chemical precursors.
"""

import typer
from rich import print
from rich.table import Table
import pypatent
from scholarly import scholarly
import requests
from bs4 import BeautifulSoup
from io import BytesIO
import pdfplumber
import docx
import csv
import re
import pubchempy as pcp
import json

chemint_app = typer.Typer()


@chemint_app.command(name="monitor-patents-research")
def monitor_patents_research(
    keywords: str = typer.Option(
        ...,
        "--keywords",
        "-k",
        help="Keywords to search for in patents and research papers.",
    ),
    start_date: str = typer.Option(
        None, "--start-date", "-s", help="Start date for patent search (YYYY-MM-DD)."
    ),
    end_date: str = typer.Option(
        None, "--end-date", "-e", help="End date for patent search (YYYY-MM-DD)."
    ),
    limit: int = typer.Option(10, "--limit", "-l", help="Limit the number of results."),
):
    """
    Monitor patents and research for new developments.
    """
    print(f"Monitoring patents and research for keywords: {keywords}")

    # Search for patents

    try:
        print("\n[bold]Patents (USPTO):[/bold]")
        search = pypatent.Search(keywords, results_limit=limit)
        patents = search.results
        
        if callable(patents):
            patents = patents()
        
        # FIX: Ensure robust checking for patents list
        if patents is not None and len(patents) > 0:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Title")
            table.add_column("URL")
            for patent in patents:
                table.add_row(patent.title, patent.url)
            print(table)
        else:
            print("No patents found on USPTO.")
    except Exception as e:
        print(f"[red]Error searching for patents on USPTO: {e}[/red]")

    try:
        print("\n[bold]Research Papers (Google Scholar):[/bold]")
        search_query = scholarly.search_pubs(keywords)
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Title")
        table.add_column("URL")
        for i, pub in enumerate(search_query):
            if i >= limit:
                break
            table.add_row(
                pub["bib"]["title"], pub.get("eprint_url", "No URL available")
            )
        print(table)
    except Exception as e:
        print(f"[red]Error searching for research papers: {e}[/red]")
        print(
            "[yellow]Note: Google Scholar may block requests. Consider using proxies.[/yellow]"
        )


@chemint_app.command(name="track-precursors")
def track_precursors(
    precursors: str = typer.Option(
        ...,
        "--precursors",
        "-p",
        help="Comma-separated list of chemical precursors to track.",
    ),
    output_file: str = typer.Option(
        "precursor_tracking.csv", "--output", "-o", help="Output CSV file."
    ),
):
    """
    Track the sale and shipment of dual-use chemical precursors.
    """
    print(f"Tracking precursors: {precursors}")

    target_urls = {
        "Sigma-Aldrich": "https://www.sigmaaldrich.com/search/{precursor}?focus=products&page=1&perpage=30&sort=relevance&term={precursor}&type=product",
        "Fisher Scientific": "https://www.fishersci.com/us/en/catalog/search/products?keyword={precursor}",
        "VWR": "https://us.vwr.com/store/search?keyword={precursor}",
    }

    results = []

    for precursor in precursors.split(","):
        precursor = precursor.strip()
        print(f"\n[bold]Tracking {precursor}...[/bold]")
        for supplier, url_template in target_urls.items():
            url = url_template.format(precursor=precursor)
            try:
                response = requests.get(url, timeout=15)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, "html.parser")

                if supplier == "Sigma-Aldrich":
                    products = soup.find_all("li", {"class": "list-group-item"})
                    for product in products:
                        name_tag = product.find("a", {"class": "product-name"})
                        price_tag = product.find("span", {"class": "price"})
                        if name_tag and price_tag:
                            name = name_tag.text.strip()
                            price = price_tag.text.strip()
                            results.append([supplier, precursor, name, price, url])
                elif supplier == "Fisher Scientific":
                    products = soup.find_all("div", {"class": "product_pod"})
                    for product in products:
                        name_tag = product.find("a", {"class": "title-link"})
                        price_tag = product.find("span", {"class": "price_value"})
                        if name_tag and price_tag:
                            name = name_tag.text.strip()
                            price = price_tag.text.strip()
                            results.append([supplier, precursor, name, price, url])
                elif supplier == "VWR":
                    products = soup.find_all("div", {"class": "search-item"})
                    for product in products:
                        name_tag = product.find("a", {"class": "search-item__title"})
                        price_tag = product.find(
                            "span", {"class": "search-item__price"}
                        )
                        if name_tag and price_tag:
                            name = name_tag.text.strip()
                            price = price_tag.text.strip()
                            results.append([supplier, precursor, name, price, url])
                print(f"  - Scraped {supplier} for {precursor}")
            except requests.exceptions.RequestException as e:
                print(f"  - [red]Error scraping {supplier}: {e}[/red]")
            except Exception as e:
                print(f"  - [red]Error parsing {supplier} data: {e}[/red]")
    # Save results to a CSV file

    if results:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Supplier", "Precursor", "Product Name", "Price", "URL"])
            writer.writerows(results)
        # FIX #1: Removed rich markup to prevent unexpected newline insertion by the CliRunner.
        print(f"Precursor tracking data saved to {output_file}")
    else:
        print("\n[yellow]No precursor data was found.[/yellow]")


@chemint_app.command(name="analyze-sds")
def analyze_sds(
    sds_url: str = typer.Option(
        ..., "--sds-url", "-u", help="URL to the Safety Data Sheet (SDS) to analyze."
    )
):
    """
    Analyze a Safety Data Sheet (SDS) to extract chemical properties and safety information.
    """
    print(f"Analyzing SDS from URL: {sds_url}")

    try:
        response = requests.get(sds_url, timeout=15)
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "")

        text_content = ""

        if "pdf" in content_type:
            with pdfplumber.open(BytesIO(response.content)) as pdf:
                for page in pdf.pages:
                    text_content += page.extract_text()
        elif (
            "vnd.openxmlformats-officedocument.wordprocessingml.document"
            in content_type
        ):
            document = docx.Document(BytesIO(response.content))
            for para in document.paragraphs:
                text_content += para.text + "\n"
        else:
            soup = BeautifulSoup(response.text, "html.parser")
            text_content = soup.get_text()
        print("\n[bold]Extracted SDS Information:[/bold]")

        # Use regex to find GHS pictograms, Hazard statements (H-statements), and
        # Precautionary statements (P-statements. These are examples and may
        # need to be refined for better accuracy.

        ghs_pictograms = re.findall(r"GHS\d{2}", text_content)
        h_statements = re.findall(r"H\d{3}", text_content)
        p_statements = re.findall(r"P\d{3}", text_content)

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Information Type")
        table.add_column("Details")
        table.add_row("GHS Pictograms", ", ".join(set(ghs_pictograms)) or "Not found")
        table.add_row("Hazard Statements", ", ".join(set(h_statements)) or "Not found")
        table.add_row(
            "Precautionary Statements", ", ".join(set(p_statements)) or "Not found"
        )
        print(table)
    except requests.exceptions.RequestException as e:
        print(f"[red]Error downloading SDS: {e}[/red]")
    except Exception as e:
        print(f"[red]An unexpected error occurred: {e}[/red]")


@chemint_app.command(name="monitor-chemical-news")
def monitor_chemical_news(
    keywords: str = typer.Option(
        ..., "--keywords", "-k", help="Keywords to search for in chemical news."
    ),
    limit: int = typer.Option(10, "--limit", "-l", help="Limit the number of results."),
):
    """
    Monitor the latest news and developments in the chemical industry.
    """
    print(f"Monitoring chemical news for keywords: {keywords}")

    news_sources = {
        "Chemical & Engineering News": "https://cen.acs.org/search.html?q={keywords}",
        "Chemistry World": "https://www.chemistryworld.com/search-results?q={keywords}",
        "ICIS": "https://www.icis.com/explore/resources/news/?s={keywords}",
    }

    results = []

    for source, url_template in news_sources.items():
        url = url_template.format(keywords=keywords)
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")

            if source == "Chemical & Engineering News":
                articles = soup.find_all("div", {"class": "search-result"}, limit=limit)
                for article in articles:
                    title_tag = article.find("a")
                    if title_tag:
                        title = title_tag.text.strip()
                        link = title_tag["href"]
                        if not link.startswith("http"):
                            base_url = "/".join(url.split("/")[:3])
                            # FIX #2: Ensure the relative link starts with a '/' before joining (most robust fix without urljoin).
                            if not link.startswith('/'):
                                link = '/' + link
                            link = base_url + link
                        results.append([source, title, link])
            elif source == "Chemistry World":
                articles = soup.find_all(
                    "div", {"class": "story-listing-item"}, limit=limit
                )
                for article in articles:
                    title_tag = article.find("a")
                    if title_tag:
                        title = title_tag.text.strip()
                        link = title_tag["href"]
                        if not link.startswith("http"):
                            base_url = "/".join(url.split("/")[:3])
                            # FIX #2: Ensure the relative link starts with a '/' before joining.
                            if not link.startswith('/'):
                                link = '/' + link
                            link = base_url + link
                        results.append([source, title, link])
            elif source == "ICIS":
                articles = soup.find_all("article", limit=limit)
                for article in articles:
                    title_tag = article.find("a")
                    if title_tag:
                        title = title_tag.text.strip()
                        link = title_tag["href"]
                        if not link.startswith("http"):
                            base_url = "/".join(url.split("/")[:3])
                            # FIX #2: Ensure the relative link starts with a '/' before joining.
                            if not link.startswith('/'):
                                link = '/' + link
                            link = base_url + link
                        results.append([source, title, link])
        except requests.exceptions.RequestException as e:
            print(f"[red]Error scraping {source}: {e}[/red]")
        except Exception as e:
            print(f"[red]Error parsing {source} data: {e}[/red]")
    if results:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Source")
        table.add_column("Title")
        table.add_column("URL")
        for row in results:
            table.add_row(*row)
        print(table)
    else:
        print("\n[yellow]No chemical news found.[/yellow]")


@chemint_app.command(name="lookup")
def lookup(
    cid: int = typer.Option(..., "--cid", "-c", help="PubChem CID to lookup."),
    output_file: str = typer.Option(None, "--output", "-o", help="Output JSON file."),
):
    """
    Lookup chemical properties from PubChem.
    """
    print(f"Looking up chemical properties for CID: {cid}")
    try:
        compound = pcp.Compound.from_cid(cid)
        result = {
            "cid": compound.cid,
            "molecular_formula": compound.molecular_formula,
            "molecular_weight": compound.molecular_weight,
            "iupac_name": compound.iupac_name,
            "canonical_smiles": compound.canonical_smiles,
        }
        print("\n[bold]Chemical Properties:[/bold]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Property")
        table.add_column("Value")
        for key, value in result.items():
            table.add_row(key, str(value))
        print(table)
        if output_file:
            with open(output_file, "w") as f:
                json.dump({"total_results": 1, "results": [result]}, f, indent=2)
            print(f"\n[green]Results saved to {output_file}[/green]")
    except Exception as e:
        print(f"[red]Error looking up chemical properties: {e}[/red]")


if __name__ == "__main__":
    chemint_app()