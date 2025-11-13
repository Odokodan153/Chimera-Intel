# Chimera-Intel/src/chimera_intel/core/polint.py

import asyncio
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup
import httpx
import typer
from rich.console import Console
from rich.table import Table

from chimera_intel.core.ai_core import AICore
from chimera_intel.core.http_client import AsyncHTTPClient
from chimera_intel.core.graph_db import GraphDB, Node, Edge
# Assuming config_loader and service initialization is handled by the main app
# from chimera_intel.core.config_loader import Config

# Configure logger
logger = logging.getLogger(__name__)

# --- Core Class ---

class PolInt:
    """
    POLINT (Policy & Regulatory Intelligence)
    
    A strategic module to proactively monitor and analyze changes in 
    legislation and regulation, assessing their potential impact.
    
    Integrates with:
    - AsyncHTTPClient: To fetch data from web portals.
    - AICore: To analyze text and assess impact.
    - GraphDB: To store findings and relationships.
    """

    def __init__(self, 
                 ai_core: AICore, 
                 http_client: AsyncHTTPClient, 
                 graph: GraphDB):
        self.ai_core = ai_core
        self.http_client = http_client
        self.graph = graph
        logger.info("POLINT module initialized.")

    async def analyze_document_impact(self, 
                                      document_text: str, 
                                      target_company: str, 
                                      target_industry: str) -> Dict[str, Any]:
        """
        Uses AICore to analyze a piece of legislation or regulation 
        for its potential impact.
        """
        logger.info(f"Analyzing document impact for {target_company} in {target_industry}")
        
        prompt = f"""
        Analyze this proposed legislation and summarize its potential financial and 
        operational impact on {target_company}, which operates in the {target_industry} sector.
        
        Document Content:
        ---
        {document_text[:8000]} 
        ---
        
        Provide your analysis in a structured format:
        Summary: [Brief summary of the legislation]
        Financial_Impact: [Potential financial impact, e.g., 'High', 'Medium', 'Low', 'None']
        Operational_Impact: [Potential operational impact, e.g., 'High', 'Medium', 'Low', 'None']
        Key_Concerns: [List of key concerns or changes required]
        Opportunity_Areas: [List of potential opportunities, if any]
        """
        
        try:
            response_text = await self.ai_core.generate_response(prompt)
            
            # Simple parsing of the structured response.
            parsed_response = {}
            current_key = ""
            for line in response_text.split('\n'):
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip().lower().replace(" ", "_")
                    parsed_response[key] = val.strip()
                    current_key = key
                elif current_key and line.strip() and not key.startswith("-"):
                    # Append to the last key if it's a multi-line value
                    parsed_response[current_key] += " " + line.strip()
                    
            if 'summary' not in parsed_response:
                logger.warning("AI response parsing failed, returning raw text.")
                return {"summary": response_text, "financial_impact": "Unknown", "operational_impact": "Unknown"}

            return parsed_response

        except Exception as e:
            logger.error(f"Error during AI impact analysis: {e}")
            return {"error": str(e)}

    async def store_findings(self, 
                             analysis: Dict[str, Any], 
                             source_url: str, 
                             target_company: str,
                             document_title: str) -> None:
        """
        Stores the analysis findings in the GraphDB.
        """
        logger.info(f"Storing findings for '{document_title}' in GraphDB.")
        
        try:
            # 1. Ensure Target Company node exists
            company_node = Node(
                id=target_company.lower().replace(" ", "_"),
                label="Company",
                properties={"name": target_company}
            )
            await self.graph.add_node(company_node)

            # 2. Create Policy Issue node
            policy_node_id = f"policy:{document_title.lower().replace(' ', '_')[:50]}"
            policy_node = Node(
                id=policy_node_id,
                label="PolicyIssue",
                properties={
                    "title": document_title,
                    "source_url": source_url,
                    "summary": analysis.get('summary', 'N/A'),
                    "financial_impact": analysis.get('financial_impact', 'Unknown'),
                    "operational_impact": analysis.get('operational_impact', 'Unknown')
                }
            )
            await self.graph.add_node(policy_node)

            # 3. Link Company to Policy Issue
            edge = Edge(
                id=f"{company_node.id}_affected_by_{policy_node.id}",
                from_node=company_node.id,
                to_node=policy_node.id,
                label="AFFECTED_BY",
                properties={"type": "Policy"}
            )
            await self.graph.add_edge(edge)
            
            logger.info(f"Successfully stored policy issue {policy_node.id} and linked to {company_node.id}")

        except Exception as e:
            logger.error(f"Error storing findings in GraphDB: {e}")

    async def process_legislative_feed(self, 
                                       base_url: str, 
                                       feed_path: str,
                                       link_selector: str,
                                       keywords: List[str], 
                                       target_company: str, 
                                       target_industry: str) -> List[Dict[str, Any]]:
        """
        Fetches a legislative feed, parses for links, filters by keywords,
        and triggers analysis for matching documents.
        """
        url = urljoin(base_url, feed_path)
        logger.info(f"Processing legislative feed from: {url}")
        
        try:
            # Use httpx directly if http_client is not setup for async context
            async with httpx.AsyncClient() as client:
                response = await client.get(url)
                response.raise_for_status()
                
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.select(link_selector)
                logger.info(f"Found {len(links)} potential links using selector '{link_selector}'")
                
                all_findings = []
                
                for link in links:
                    document_title = link.get_text().strip()
                    document_url = urljoin(base_url, link.get('href'))
                    
                    if not document_title or not document_url:
                        continue
                    
                    # Check if keywords are present in the title
                    if any(keyword.lower() in document_title.lower() for keyword in keywords):
                        logger.info(f"Keyword match found: '{document_title}' at {document_url}")
                        
                        # Fetch the full document text
                        try:
                            doc_response = await client.get(document_url)
                            doc_response.raise_for_status()
                            doc_soup = BeautifulSoup(doc_response.text, 'html.parser')
                            document_text = doc_soup.get_text(separator=' ', strip=True)

                            if not document_text:
                                logger.warning(f"No text found in document: {document_url}")
                                continue

                            # Run AI analysis
                            analysis = await self.analyze_document_impact(
                                document_text=document_text,
                                target_company=target_company,
                                target_industry=target_industry
                            )
                            
                            if 'error' not in analysis:
                                # Store findings
                                await self.store_findings(
                                    analysis=analysis,
                                    source_url=document_url,
                                    target_company=target_company,
                                    document_title=document_title
                                )
                                analysis['source_url'] = document_url
                                analysis['title'] = document_title
                                all_findings.append(analysis)
                            else:
                                logger.error(f"Skipping storage due to analysis error: {analysis['error']}")

                        except httpx.HTTPStatusError as e:
                            logger.error(f"Failed to fetch document {document_url}: {e}")
                        except Exception as e:
                            logger.error(f"Error processing document {document_url}: {e}")
                
                logger.info(f"POLINT processing complete. Found {len(all_findings)} relevant documents.")
                return all_findings

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to fetch legislative feed {url}: {e}")
            return []
        except Exception as e:
            logger.error(f"An unexpected error occurred during legislative feed processing: {e}")
            return []


# --- CLI ---

polint_app = typer.Typer(
    name="polint",
    help="Proactive Policy & Regulatory Intelligence (POLINT) tools."
)
console = Console()

def get_polint_service():
    """Initializes and returns a PolInt service instance."""
    # This is a simplified bootstrap.
    # In the real app, this would use a central service locator
    # or dependency injection framework provided by the main Chimera app.
    try:
        ai_core = AICore()
        http_client = AsyncHTTPClient()
        graph_db = GraphDB()
        
        # Connect to GraphDB asynchronously
        try:
            asyncio.run(graph_db.connect())
        except Exception as e:
            logger.warning(f"Could not connect to GraphDB in CLI helper: {e}. Proceeding without graph.")
            # We can still proceed, store_findings will just fail gracefully.
        
        return PolInt(ai_core=ai_core, http_client=http_client, graph=graph_db)
    except Exception as e:
        console.print(f"[bold red]Failed to initialize core services:[/bold red] {e}")
        console.print("Please ensure API keys (e.g., GEMINI_API_KEY) and database connection (e.g., NEO4J_URI) are set in your environment.")
        raise typer.Exit(code=1)

@polint_app.command(
    name="track-portal",
    help="Scan a legislative portal for keywords and run AI impact analysis."
)
def track_portal(
    base_url: str = typer.Option(
        ...,
        help="The base URL of the legislative portal (e.g., 'https://www.congress.gov')."
    ),
    feed_path: str = typer.Option(
        "/",
        help="The path to the feed or page with links (e.g., '/search?q=...')."
    ),
    link_selector: str = typer.Option(
        ...,
        help="CSS selector to find the links to documents (e.g., 'li.result-item a')."
    ),
    keywords: List[str] = typer.Option(
        ...,
        "--keyword",
        help="Keyword to filter document titles (case-insensitive). Can be used multiple times."
    ),
    target_company: str = typer.Option(
        ...,
        help="The target company name for impact analysis."
    ),
    target_industry: str = typer.Option(
        ...,
        help="The target industry for impact analysis."
    )
):
    """
    CLI command to execute a POLINT scan on a specific web portal.
    """
    console.print(f"[bold green]Starting POLINT scan for '{target_company}'[/bold green]")
    console.print(f"Tracking: [cyan]{base_url}{feed_path}[/cyan] with keywords: [yellow]{keywords}[/yellow]")
    
    service = None
    try:
        service = get_polint_service()
        
        async def main():
            return await service.process_legislative_feed(
                base_url=base_url,
                feed_path=feed_path,
                link_selector=link_selector,
                keywords=keywords,
                target_company=target_company,
                target_industry=target_industry
            )
        
        results = asyncio.run(main())
        
        if not results:
            console.print("[yellow]Scan complete. No matching policy documents found.[/yellow]")
            return

        console.print(f"[bold green]Scan complete. Found {len(results)} relevant documents.[/bold green]")
        
        table = Table(title="POLINT Analysis Results")
        table.add_column("Title", style="cyan", no_wrap=False)
        table.add_column("Financial Impact", style="magenta")
        table.add_column("Operational Impact", style="magenta")
        table.add_column("Summary", style="white")
        
        for res in results:
            table.add_row(
                res.get('title', 'N/A'),
                res.get('financial_impact', 'N/A'),
                res.get('operational_impact', 'N/A'),
                res.get('summary', 'N/A')
            )
            
        console.print(table)
        console.print("\n[bold]All findings have been stored in the GraphDB (if connection was successful).[/bold]")

    except Exception as e:
        logger.error(f"POLINT CLI command failed: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    finally:
        # Gracefully close connections
        if service and service.graph:
            try:
                asyncio.run(service.graph.close())
            except Exception as e:
                logger.warning(f"Error closing graph connection: {e}")
        if service and service.http_client:
            try:
                asyncio.run(service.http_client.close())
            except Exception as e:
                logger.warning(f"Error closing HTTP client: {e}")
