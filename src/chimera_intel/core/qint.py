import typer
import feedparser
import requests
from bs4 import BeautifulSoup
from bs4.element import Tag
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True, help="Quantum Intelligence (QINT) tools.")
console = Console()


class QInt:
    """
    Handles QINT tasks such as scraping quantum research, analyzing technology
    readiness, and monitoring Post-Quantum Cryptography (PQC) developments.
    """

    def scrape_quantum_research(self, keyword: str, max_results: int = 10) -> list:
        """
        Scrapes the latest quantum research papers from arXiv.org.
        """
        try:
            url = f"http://export.arxiv.org/api/query?search_query=all:{keyword}&start=0&max_results={max_results}&sortBy=submittedDate&sortOrder=descending"
            feed = feedparser.parse(url)

            papers = []
            for entry in feed.entries:
                papers.append(
                    {
                        "title": entry.title,
                        "authors": ", ".join(author.name for author in entry.authors),
                        "published": entry.published,
                        "link": entry.link,
                    }
                )
            return papers
        except Exception as e:
            console.print(f"[bold red]Error scraping arXiv: {e}[/bold red]")
            return []

    def analyze_trl(self, entity: str) -> dict:
        """
        Provides a Technology Readiness Level (TRL) analysis based on public data
        by scraping Wikipedia for mentions of quantum computing milestones.
        This is a qualitative assessment and not a hard real-time metric.
        """
        try:
            search_url = f"https://en.wikipedia.org/w/index.php?search={entity.replace(' ', '+')}+quantum+computing"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
            }
            response = requests.get(search_url, headers=headers)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "html.parser")

            # Heuristics for TRL estimation based on keywords in search results

            page_text = soup.get_text().lower()
            score = 3  # Baseline for having a presence
            assessment = "General research and activity in the quantum space."

            if "quantum supremacy" in page_text or "fault-tolerant" in page_text:
                score = 8
                assessment = "Demonstrated significant milestones (e.g., quantum supremacy) and is likely focused on error correction and scaling."
            elif any(
                s in page_text
                for s in [
                    "qubit roadmap",
                    "publicly available quantum computer",
                    "quantum volume",
                ]
            ):
                score = 7
                assessment = "Advanced hardware development with a clear public roadmap and accessible quantum systems."
            elif any(
                s in page_text
                for s in ["quantum communication", "qkd", "quantum sensing"]
            ):
                score = 6
                assessment = "Strong focus on specific quantum applications like communication or sensing, with developed prototypes."
            elif "funding" in page_text or "initiative" in page_text:
                score = 5
                assessment = "Significant investment and national/corporate initiatives are in place, focus is on building foundational capabilities."
            return {
                "entity": entity,
                "estimated_trl": score,
                "scale": "1 (Basic Research) to 9 (System Proven)",
                "assessment": assessment,
            }
        except Exception as e:
            console.print(f"[bold red]Error analyzing TRL for {entity}: {e}[/bold red]")
            return {"entity": entity, "error": "Could not perform TRL analysis."}

    def monitor_pqc(self) -> list:
        """
        Monitors the status of the NIST Post-Quantum Cryptography (PQC) standardization process.
        """
        try:
            url = "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
            response = requests.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "html.parser")

            algorithms = []
            # Find the table with the finalists for standardization

            table = soup.find("table", caption="Algorithms to be Standardized")
            if table:
                tbody = table.find("tbody")
                if isinstance(tbody, Tag):
                    for row in tbody.find_all("tr"):
                        cols = row.find_all("td")
                        if len(cols) >= 2:
                            algorithms.append(
                                {
                                    "algorithm": cols[0].text.strip(),
                                    "type": cols[1].text.strip(),
                                    "status": "Selected for Standardization",
                                }
                            )
            return algorithms
        except Exception as e:
            console.print(f"[bold red]Error scraping NIST PQC page: {e}[/bold red]")
            return []


@app.command(name="research")
def research(
    keyword: str = typer.Argument(
        "quantum computing", help="Keyword to search for in quantum research papers."
    ),
    limit: int = typer.Option(
        5, "--limit", "-l", help="Number of recent papers to display."
    ),
):
    """Scrapes recent quantum research from arXiv.org."""
    qint = QInt()
    papers = qint.scrape_quantum_research(keyword, limit)
    if papers:
        table = Table(title=f"Recent Research on '{keyword}' from arXiv")
        table.add_column("Published", style="yellow")
        table.add_column("Title", style="cyan")
        table.add_column("Authors", style="magenta")
        for p in papers:
            table.add_row(p["published"].split("T")[0], p["title"], p["authors"])
        console.print(table)


@app.command(name="trl-analysis")
def trl_analysis(
    entity: str = typer.Argument(
        ..., help="Company or country to analyze (e.g., Google, IBM, China)."
    )
):
    """Provides a Technology Readiness Level (TRL) score based on public data."""
    qint = QInt()
    result = qint.analyze_trl(entity)
    console.print_json(data=result)


@app.command(name="pqc-status")
def pqc_status():
    """Monitors the NIST Post-Quantum Cryptography (PQC) standardization process."""
    qint = QInt()
    algorithms = qint.monitor_pqc()
    if algorithms:
        table = Table(title="NIST Post-Quantum Cryptography Standardization Status")
        table.add_column("Algorithm", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Status", style="green")
        for alg in algorithms:
            table.add_row(alg["algorithm"], alg["type"], alg["status"])
        console.print(table)


if __name__ == "__main__":
    app()