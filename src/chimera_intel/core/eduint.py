"""
EDUINT CLI for Educational & Research Intelligence.

Monitors academic publications, university patent filings, tech transfer announcements,
and curriculum changes to identify emerging skills and innovations. Data is retrieved
from web sources, analyzed using AI, and stored in a graph database for alerts and tracking.
"""

import typer
from rich.console import Console
from typing import List, Dict, Any, Optional
import logging
from chimera_intel.core.gemini_client import GeminiClient
from chimera_intel.core.web_scraper import WebScraper
from chimera_intel.core.google_search import GoogleSearch
from chimera_intel.core.grey_literature import GreyLiterature
from chimera_intel.core.alert_manager import AlertManager
from chimera_intel.core.graph_db import GraphDB, Node, Relationship
from chimera_intel.core.schemas import IntelType

# Configure logging
logger = logging.getLogger(__name__)

app = typer.Typer()
console = Console()

class Eduint:
    """
    Handles Educational & Research Intelligence (EDUINT).
    
    This class tracks sources of innovation by monitoring universities,
    research labs, patent filings, and curriculum changes.
    """
    
    def __init__(
        self,
        gemini_client: Optional[GeminiClient] = None,
        scraper: Optional[WebScraper] = None,
        search_client: Optional[GoogleSearch] = None,
        grey_lit: Optional[GreyLiterature] = None,
        alerter: Optional[AlertManager] = None,
        graph: Optional[GraphDB] = None
    ):
        self.gemini = gemini_client if gemini_client else GeminiClient()
        self.scraper = scraper if scraper else WebScraper()
        self.search = search_client if search_client else GoogleSearch()
        self.grey_lit = grey_lit if grey_lit else GreyLiterature()
        self.alerter = alerter if alerter else AlertManager()
        self.graph = graph if graph else GraphDB()
        logger.info("EDUINT module initialized.")

    def monitor_publications(self, targets: List[str]) -> Dict[str, Any]:
        """
        Monitors specific academic figures, labs, or universities for new publications.

        Args:
            targets: A list of names to search for (e.g., "Geoffrey Hinton", "MIT CSAIL").

        Returns:
            A dictionary containing new publications found for each target.
        """
        console.print(f"[bold cyan]Monitoring publications for targets: {targets}[/bold cyan]")
        all_new_publications = {}

        for target in targets:
            try:
                # Use existing GreyLiterature module to find papers
                # Assuming search_semantic_scholar returns a list of paper dicts
                papers = self.grey_lit.search_semantic_scholar(target, limit=5)
                new_finds = []

                # Check if paper already exists in graph
                for paper in papers:
                    paper_title = paper.get('title', 'Unknown Title')
                    paper_id = paper.get('paperId', paper_title)
                    
                    if not self.graph.node_exists("Publication", paper_id):
                        console.print(f"  [green]New publication found for {target}: {paper_title}[/green]")
                        new_finds.append(paper)
                        
                        # Add to graph
                        paper_node = Node(
                            "Publication",
                            paper_id,
                            properties={
                                'title': paper_title,
                                'author': ", ".join(paper.get('authors', [])),
                                'year': paper.get('year', 'N/A'),
                                'source': 'semantic_scholar',
                                'intel_type': IntelType.EDUINT.value
                            }
                        )
                        self.graph.add_node(paper_node)
                        
                        # Link to target (e.g., a Person or Organization node)
                        self.graph.add_relationship(
                            Relationship(
                                "MonitoredTarget", 
                                target, 
                                "PUBLISHED", 
                                "Publication", 
                                paper_id
                            )
                        )
                    
                if new_finds:
                    all_new_publications[target] = new_finds
                    self.alerter.send_alert(
                        f"EDUINT: New Publications Found for {target}",
                        f"Found {len(new_finds)} new paper(s). First hit: {new_finds[0]['title']}"
                    )

            except Exception as e:
                logger.error(f"Failed to monitor publications for {target}: {e}")
                console.print(f"  [red]Error monitoring {target}: {e}[/red]")
                
        return all_new_publications

    def track_patents_and_tech_transfer(self, institutions: List[str]) -> Dict[str, Any]:
        """
        Tracks university patent filings and tech transfer office announcements.

        Args:
            institutions: List of institutions (e.g., "Stanford University").

        Returns:
            A dictionary of new patents or announcements found.
        """
        console.print(f"[bold cyan]Tracking patents/tech transfer for: {institutions}[/bold cyan]")
        all_new_patents = {}

        for inst in institutions:
            try:
                # 1. Find the tech transfer or patent office URL
                query = f"{inst} technology transfer office announcements"
                search_results = self.search.search(query, num_results=1)
                
                if not search_results:
                    console.print(f"  [yellow]Could not find tech transfer office for {inst}.[/yellow]")
                    continue

                url = search_results[0]['link']
                console.print(f"  Scraping {url} for {inst}...")
                
                # 2. Scrape the content
                scraped_text = self.scraper.scrape_url(url, return_text=True)
                if not scraped_text or len(scraped_text) < 100:
                    console.print(f"  [yellow]No useful content scraped from {url}.[/yellow]")
                    continue

                # 3. Use Gemini to analyze the text
                prompt = f"""
                Analyze the following text from {inst}'s tech transfer office.
                Extract any new patent filings, licensed technologies, or major innovation announcements.
                Return a JSON list of objects, each with 'title', 'summary', and 'type' ('Patent', 'License', 'Announcement').
                
                Text:
                {scraped_text[:8000]} 
                """
                analysis = self.gemini.chat(prompt)
                
                # Assuming gemini.chat returns a JSON string
                import json
                extracted_items = json.loads(analysis)
                
                new_finds = []
                for item in extracted_items:
                    item_title = item.get('title', 'Unknown Item')
                    if not self.graph.node_exists("Patent", item_title):
                        console.print(f"  [green]New Tech Transfer Item for {inst}: {item_title}[/green]")
                        new_finds.append(item)
                        
                        # Add to graph
                        item_node = Node(
                            "Patent" if item.get('type') == 'Patent' else "TechAnnouncement",
                            item_title,
                            properties={
                                'summary': item.get('summary', ''),
                                'type': item.get('type', 'N/A'),
                                'source': url,
                                'intel_type': IntelType.EDUINT.value
                            }
                        )
                        self.graph.add_node(item_node)
                        self.graph.add_relationship(
                            Relationship("Organization", inst, "ANNOUNCED", item_node.label, item_node.id)
                        )
                        
                if new_finds:
                    all_new_patents[inst] = new_finds
                    self.alerter.send_alert(
                        f"EDUINT: New Tech Transfer Item for {inst}",
                        f"Found {len(new_finds)} new items. First hit: {new_finds[0]['title']}"
                    )

            except Exception as e:
                logger.error(f"Failed to track patents for {inst}: {e}")
                console.print(f"  [red]Error tracking patents for {inst}: {e}[/red]")
                
        return all_new_patents

    def analyze_curriculum_changes(self, institution: str, department: str) -> Dict[str, Any]:
        """
        Analyzes curriculum changes at key institutions to spot emerging skills.

        Args:
            institution: The university (e.g., "Carnegie Mellon University").
            department: The department (e.g., "Computer Science").

        Returns:
            A dictionary containing analysis results, including new skills.
        """
        console.print(f"[bold cyan]Analyzing curriculum for {department} at {institution}[/bold cyan]")
        
        try:
            # 1. Find the curriculum page
            query = f"{institution} {department} course catalog"
            search_results = self.search.search(query, num_results=1)
            if not search_results:
                console.print(f"  [yellow]Could not find curriculum page.[/yellow]")
                return {}

            url = search_results[0]['link']
            console.print(f"  Scraping {url}...")

            # 2. Scrape the content
            scraped_text = self.scraper.scrape_url(url, return_text=True)
            if not scraped_text or len(scraped_text) < 100:
                console.print(f"  [yellow]No useful content scraped from {url}.[/yellow]")
                return {}

            # 3. Use Gemini to analyze
            prompt = f"""
            Analyze the following course list/curriculum for the {department}
            department at {institution}. Identify new or emerging, in-demand
            technical skills, topics, or course titles. 
            
            Look for keywords like 'Prompt Engineering', 'Large Language Models',
            'Quantum Computing', 'Generative AI', etc., that were not common
            a few years ago.
            
            Return a JSON object with a key 'emerging_skills' (a list of strings)
            and 'analysis_summary' (a brief text summary).

            Text:
            {scraped_text[:8000]}
            """
            analysis_str = self.gemini.chat(prompt)
            
            import json
            analysis = json.loads(analysis_str)
            
            emerging_skills = analysis.get('emerging_skills', [])
            summary = analysis.get('analysis_summary', 'No summary.')

            console.print(f"  [green]Analysis Complete:[/green] {summary}")

            if emerging_skills:
                console.print(f"  [bold magenta]Emerging Skills Identified: {emerging_skills}[/bold magenta]")
                for skill in emerging_skills:
                    if not self.graph.node_exists("EmergingSkill", skill):
                        # Add to graph
                        skill_node = Node(
                            "EmergingSkill",
                            skill,
                            properties={'intel_type': IntelType.EDUINT.value}
                        )
                        self.graph.add_node(skill_node)
                        self.graph.add_relationship(
                             Relationship("Organization", institution, "TEACHES", "EmergingSkill", skill)
                        )
                
                self.alerter.send_alert(
                    f"EDUINT: Emerging Skills Detected at {institution}",
                    f"Analysis of {department} curriculum found: {', '.join(emerging_skills)}"
                )
            
            return analysis
            
        except Exception as e:
            logger.error(f"Failed to analyze curriculum for {institution}: {e}")
            console.print(f"  [red]Error analyzing curriculum: {e}[/red]")
            return {}

# --- Typer CLI Commands ---

@app.command()
def monitor_publications(
    targets: List[str] = typer.Option(..., "--target", help="Academic figure, lab, or university to monitor.")
):
    """
    Monitors specified targets for new academic publications.
    """
    eduint = Eduint()
    results = eduint.monitor_publications(targets)
    if not results:
        console.print("[yellow]No new publications found for the specified targets.[/yellow]")

@app.command()
def track_patents(
    institutions: List[str] = typer.Option(..., "--inst", help="Institution to track for patents and tech transfer.")
):
    """
    Tracks patent filings and tech transfer announcements from key institutions.
    """
    eduint = Eduint()
    results = eduint.track_patents_and_tech_transfer(institutions)
    if not results:
        console.print("[yellow]No new patents or announcements found.[/yellow]")

@app.command()
def analyze_curriculum(
    institution: str = typer.Option(..., "--inst", help="The university or institution."),
    department: str = typer.Option(..., "--dept", help="The specific department (e.g., 'Computer Science').")
):
    """
    Analyzes curriculum changes at a target institution to spot emerging technical skills.
    """
    eduint = Eduint()
    eduint.analyze_curriculum_changes(institution, department)

if __name__ == "__main__":
    app()