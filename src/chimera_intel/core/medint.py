import typer
import logging
import requests
import feedparser
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

app = typer.Typer(
    help="MEDINT: Monitor public health, R&D, and medical supply chains."
)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants for API endpoints
CLINICAL_TRIALS_API_V2 = "https://clinicaltrials.gov/api/v2/studies"
FDA_RECALLS_API = "https://api.fda.gov/device/recall.json"
DISEASE_FEEDS = {
    "cdc_alerts": "https://tools.cdc.gov/api/v2/resources/media/132608.rss",
    "who_news": "https://www.who.int/rss-feeds/news-rss.xml",
    "ecdc": "https://www.ecdc.europa.eu/en/all-topics-rss"
}

class MedicalIntelligence:
    """
    Provides strategic intelligence on public health and pharmaceutical R&D.
    """

    def __init__(self, fda_api_key: Optional[str] = None):
        """
        Initializes the MEDINT client.

        Args:
            fda_api_key: Optional API key for openFDA (for higher rate limits).
        """
        self.fda_api_key = fda_api_key
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "MEDINT-Module/1.0"})
        logger.info("MedicalIntelligence module initialized.")

    def monitor_clinical_trials(self, company_name: str, max_trials: int = 10) -> List[Dict[str, Any]]:
        """
        Monitors ClinicalTrials.gov for a specific company (sponsor).
        
        Uses the new V2 API.
        """
        query_params = {
            "query.term": company_name,
            "query.field": "sponsor", # Search by sponsor
            "pageSize": max_trials,
            "format": "json"
        }
        
        try:
            response = self.session.get(CLINICAL_TRIALS_API_V2, params=query_params, timeout=10)
            response.raise_for_status() # Raise HTTPError for bad responses
            data = response.json()
            
            trials = []
            for study in data.get("studies", []):
                protocol = study.get("protocolSection", {})
                
                # Extract key data points
                nct_id = protocol.get("identificationModule", {}).get("nctId", "N/A")
                title = protocol.get("identificationModule", {}).get("briefTitle", "N/A")
                status = protocol.get("statusModule", {}).get("overallStatus", "N/A")
                
                conditions = protocol.get("conditionsModule", {}).get("conditions", [])
                interventions = [
                    inv.get("name", "N/A") 
                    for inv in protocol.get("armsInterventionsModule", {}).get("interventions", [])
                ]
                
                trials.append({
                    "nct_id": nct_id,
                    "title": title,
                    "status": status,
                    "conditions": conditions,
                    "interventions": interventions,
                    "link": f"https://clinicaltrials.gov/study/{nct_id}"
                })
                
            logger.info(f"Found {len(trials)} clinical trials for sponsor: {company_name}")
            return trials

        except requests.RequestException as e:
            logger.error(f"Error querying ClinicalTrials.gov API: {e}")
            return []
        except json.JSONDecodeError:
            logger.error(f"Failed to decode JSON response from ClinicalTrials.gov")
            return []

    def monitor_disease_outbreaks(self, source: str = "cdc_alerts") -> List[Dict[str, Any]]:
        """
        Ingests data from public health RSS feeds (WHO, CDC, ECDC).
        """
        feed_url = DISEASE_FEEDS.get(source)
        if not feed_url:
            logger.error(f"Invalid feed source: {source}. Valid sources are: {list(DISEASE_FEEDS.keys())}")
            return []

        try:
            feed = feedparser.parse(feed_url)
            if feed.bozo:
                logger.warning(f"Feed {feed_url} may be malformed: {feed.bozo_exception}")

            outbreaks = []
            for entry in feed.entries:
                # Convert published_parsed (struct_time) to ISO format string
                published_date = "N/A"
                if hasattr(entry, "published_parsed") and entry.published_parsed:
                    published_date = datetime(*entry.published_parsed[:6]).isoformat()
                
                outbreaks.append({
                    "title": entry.get("title", "N/A"),
                    "link": entry.get("link", "N/A"),
                    "summary": entry.get("summary", "N/A"),
                    "published": published_date,
                    "source": source
                })
            
            logger.info(f"Fetched {len(outbreaks)} items from {source} feed.")
            return outbreaks
            
        except Exception as e:
            logger.error(f"Error parsing RSS feed {feed_url}: {e}")
            return []

    def monitor_medical_supply_chain(self, item_keyword: str, max_recalls: int = 10) -> List[Dict[str, Any]]:
        """
        Monitors openFDA for medical device recalls based on a keyword.
        """
        query_params = {
            "search": f'product_description:"{item_keyword}"+OR+reason_for_recall:"{item_keyword}"',
            "limit": max_recalls
        }
        if self.fda_api_key:
            query_params["api_key"] = self.fda_api_key
        
        try:
            response = self.session.get(FDA_RECALLS_API, params=query_params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            recalls = []
            for result in data.get("results", []):
                recalls.append({
                    "recall_number": result.get("recall_number", "N/A"),
                    "recalling_firm": result.get("recalling_firm", "N/A"),
                    "product_description": result.get("product_description", "N/A"),
                    "reason_for_recall": result.get("reason_for_recall", "N/A"),
                    "recall_initiation_date": result.get("recall_initiation_date", "N/A"),
                    "status": result.get("status", "N/A")
                })
            
            logger.info(f"Found {len(recalls)} FDA device recalls for keyword: {item_keyword}")
            return recalls

        except requests.RequestException as e:
            logger.error(f"Error querying openFDA API: {e}")
            return []
        except json.JSONDecodeError:
            logger.error(f"Failed to decode JSON response from openFDA")
            return []


# --- Typer CLI Commands ---

cli_instance = MedicalIntelligence()

@app.command()
def trials(
    company_name: str = typer.Argument(..., help="The full name of the company/sponsor (e.g., 'Pfizer')."),
    max_trials: int = typer.Option(5, "--max", help="Max number of trials to return.")
):
    """
    Monitors ClinicalTrials.gov for a company's R&D pipeline.
    """
    typer.secho(f"Querying ClinicalTrials.gov for sponsor: {company_name}...", fg=typer.colors.BLUE)
    results = cli_instance.monitor_clinical_trials(company_name, max_trials)
    if not results:
        typer.secho("No results found or an error occurred.", fg=typer.colors.YELLOW)
        return
    typer.echo(json.dumps(results, indent=2))

@app.command()
def outbreaks(
    source: str = typer.Option("cdc_alerts", help=f"Data source. Options: {list(DISEASE_FEEDS.keys())}")
):
    """
    Fetches latest disease outbreak alerts from public health feeds.
    """
    typer.secho(f"Fetching latest outbreak data from {source}...", fg=typer.colors.BLUE)
    results = cli_instance.monitor_disease_outbreaks(source)
    if not results:
        typer.secho("No results found or an error occurred.", fg=typer.colors.YELLOW)
        return
    typer.echo(json.dumps(results, indent=2))

@app.command()
def supply_chain(
    keyword: str = typer.Argument(..., help="Keyword for a medical device (e.g., 'ventilator', 'pacemaker')."),
    max_recalls: int = typer.Option(5, "--max", help="Max number of recalls to return.")
):
    """
    Monitors openFDA for medical device recalls.
    """
    typer.secho(f"Querying openFDA for device recalls matching: {keyword}...", fg=typer.colors.BLUE)
    results = cli_instance.monitor_medical_supply_chain(keyword, max_recalls)
    if not results:
        typer.secho("No results found or an error occurred.", fg=typer.colors.YELLOW)
        return
    typer.echo(json.dumps(results, indent=2))

if __name__ == "__main__":
    app()