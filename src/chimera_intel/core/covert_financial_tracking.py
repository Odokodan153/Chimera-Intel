# src/chimera_intel/core/covert_financial_tracking.py
import logging
import re
import asyncio
from typing import List, Dict, Any
import typer
import json
from .mlint import (
    screen_entity_for_aml,
    identify_shell_company_indicators,
)
from .finint import get_transactions_from_db, analyze_transaction_patterns
from .corporate_intel import get_trade_data
from .dark_web_osint import search_dark_web_engine
from .graph_db import graph_db_instance, GraphDB  # For linking entities
from .ai_core import generate_swot_from_data
from .config_loader import API_KEYS
# --- End (REAL) Imports ---

logger = logging.getLogger(__name__)


class CovertFinancialTracker:
    """
    Orchestrates modules to track covert financial activities, including
    money laundering, trade-based espionage, and black market sales.
    
    This module reuses existing components (FinINT, Blockchain, Logistics, etc.)
    to provide a high-level analysis capability.
    """

    def __init__(self, graph_db: GraphDB):
        """
        Initializes the CovertFinancialTracker with necessary component modules.
        
        Args:
            graph_db: An instance of the GraphDB to link entities.
        """
        logger.info("Initializing Covert Financial Tracker")
        self.graph_db = graph_db
        # We will call real functions directly, so no need to init classes
        self.ai_api_key = API_KEYS.google_api_key

    async def track_money_laundering(self, targets: List[str]) -> Dict[str, Any]:
        """
        Tracks money laundering and dark finance activities.
        - Identifies shell companies
        - Analyzes cryptocurrency transactions
        
        Args:
            targets: A list of entity names (people, orgs) to investigate.
            
        Returns:
            A dictionary containing findings.
        """
        logger.info(f"Tracking money laundering for targets: {targets}")
        results = {"shell_company_indicators": [], "crypto_analysis": []}
        
        if not self.ai_api_key:
            results["error"] = "Google API Key not found, cannot perform analysis."
            return results

        for target in targets:
            logger.debug(f"Analyzing {target} with MLINT and FinINT")
            
            # 1. Use MLINT for shell company indicators
            shell_indicators = identify_shell_company_indicators(target)
            results["shell_company_indicators"].append({target: shell_indicators})
            
            # 2. Extract crypto addresses (simple regex)
            # In a real system, this would come from other OSINT modules
            crypto_addresses = re.findall(r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b", target)
            
            for addr in crypto_addresses:
                logger.debug(f"Analyzing crypto address {addr}")
                # Use mock transaction getter (as finint.py is mock)
                transactions = get_transactions_from_db(addr)
                if transactions:
                    # Use real AI pattern detection from finint
                    pattern_result = analyze_transaction_patterns(addr, transactions, self.ai_api_key)
                    if not pattern_result.error:
                        results["crypto_analysis"].append(pattern_result.model_dump())
                        # Link in graph
                        self.graph_db.add_node(addr, "crypto_address", {"analysis_summary": pattern_result.summary})
                        self.graph_db.add_edge(target, addr, "HAS_CRYPTO_ADDRESS")

        logger.info("Money laundering tracking complete.")
        return results

    async def track_trade_espionage(self, suspect_actors: List[str]) -> Dict[str, Any]:
        """
        Links shipments to suspect actors and uses AI to assess risk.
        
        Args:
            suspect_actors: A list of entity names to investigate.
            
        Returns:
            A dictionary containing findings.
        """
        logger.info(f"Tracking trade espionage for actors: {suspect_actors}")
        results = {"suspicious_shipments": []}

        if not self.ai_api_key:
            results["error"] = "Google API Key not found, cannot perform analysis."
            return results

        for actor in suspect_actors:
            logger.debug(f"Analyzing {actor} for trade espionage")
            
            # 1. Use real corporate_intel function to find shipments
            trade_data = get_trade_data(actor)
            if trade_data.error or not trade_data.shipments:
                continue

            # 2. Use AI Core to analyze risk of these shipments
            prompt = f"""
            Analyze the following shipments associated with '{actor}'.
            Identify any high-risk indicators for trade-based espionage,
            such as shipments to/from high-risk jurisdictions, unusual
            product descriptions, or connections to sanctioned entities.
            
            Shipments:
            {json.dumps([s.model_dump() for s in trade_data.shipments[:10]], indent=2, default=str)}
            
            Return a brief risk analysis summary.
            """
            ai_summary = generate_swot_from_data(prompt, self.ai_api_key)
            
            if not ai_summary.error:
                results["suspicious_shipments"].append({
                    "actor": actor,
                    "ai_risk_summary": ai_summary.analysis_text,
                    "shipments": trade_data.model_dump()
                })
                # Link in graph
                self.graph_db.add_node(actor, "Entity")
                for shipment in trade_data.shipments:
                    shipment_id = f"shipment_{shipment.date}_{shipment.consignee}"
                    self.graph_db.add_node(shipment_id, "Shipment", shipment.model_dump())
                    self.graph_db.add_edge(actor, shipment_id, "ASSOCIATED_WITH")

        logger.info("Trade espionage tracking complete.")
        return results

    async def scan_black_markets(self, keywords: List[str]) -> Dict[str, Any]:
        """
        Detects sales of weapons, software, or sensitive equipment
        in underground markets using real dark_web_osint.
        
        Args:
            keywords: List of keywords to search for (e.g., "weapon", "exploit").
            
        Returns:
            A dictionary containing findings.
        """
        logger.info(f"Scanning black markets with keywords: {keywords}")
        
        all_listings = []
        for keyword in keywords:
            scan_result = await search_dark_web_engine(keyword, engine="ahmia")
            if not scan_result.error and scan_result.found_results:
                all_listings.extend(scan_result.found_results)
        
        # Filter for relevant sales (simple keyword match)
        filtered_results = [
            result.model_dump() for result in all_listings 
            if any(kw in result.title.lower() or (result.description and kw in result.description.lower()) for kw in keywords)
        ]
        
        logger.info(f"Found {len(filtered_results)} relevant black market listings.")
        
        # Add to graph
        for listing in filtered_results:
            self.graph_db.add_node(listing.get("url"), "dark_web_listing", listing)
            # We can't easily get vendor, so we link the keyword
            for kw in keywords:
                if kw in listing.get("title", "").lower():
                     self.graph_db.add_node(kw, "Keyword")
                     self.graph_db.add_edge(kw, listing.get("url"), "FOUND_IN")

        return {"listings": filtered_results}

    async def run_full_analysis(self, targets: List[str], keywords: List[str]) -> Dict[str, Any]:
        """
        Runs all tracking modules for a comprehensive analysis.
        
        Args:
            targets: List of entity names for laundering/trade analysis.
            keywords: List of keywords for black market scanning.
            
        Returns:
            A comprehensive report dictionary.
        """
        logger.info(f"Running full covert financial analysis...")
        
        tasks = [
            self.track_money_laundering(targets),
            self.track_trade_espionage(targets),
            self.scan_black_markets(keywords)
        ]
        
        laundering, trade, market = await asyncio.gather(*tasks)

        full_report = {
            "money_laundering": laundering,
            "trade_espionage": trade,
            "black_market_scanning": market
        }
        
        logger.info("Full covert financial analysis complete.")
        return full_report
    
def get_cft_tracker() -> CovertFinancialTracker:
    """Typer dependency injector to get the tracker with GraphDB."""
    # Use the globally imported graph_db_instance
    return CovertFinancialTracker(graph_db=graph_db_instance)
    
cft_app = typer.Typer(
    name="cft",
    help="Covert Financial Tracking (CFT) Toolkit",
    no_args_is_help=True
)

@cft_app.command("track-laundering", help="Track shell companies, and analyze crypto transactions.")
def cli_track_laundering(
    targets: str = typer.Option(..., "--targets", help="Comma-separated list of target entities"),
):
    tracker = get_cft_tracker()
    target_list = [t.strip() for t in targets.split(',')]
    results = asyncio.run(tracker.track_money_laundering(target_list))
    typer.echo(json.dumps(results, indent=2, default=str))


@cft_app.command("track-trade", help="Link shipments to suspect actors and analyze risk.")
def cli_track_trade_espionage(
    actors: str = typer.Option(..., "--actors", help="Comma-separated list of suspect actors"),
):
    tracker = get_cft_tracker()
    actor_list = [a.strip() for a in actors.split(',')]
    results = asyncio.run(tracker.track_trade_espionage(actor_list))
    typer.echo(json.dumps(results, indent=2, default=str))


@cft_app.command("scan-markets", help="Scan black markets for weapons, software, or sensitive equipment.")
def cli_scan_black_markets(
    keywords: str = typer.Option(..., "--keywords", help="Comma-separated list of keywords (e.g., 'weapon,exploit')"),
):
    tracker = get_cft_tracker()
    keyword_list = [k.strip() for k in keywords.split(',')]
    results = asyncio.run(tracker.scan_black_markets(keyword_list))
    typer.echo(json.dumps(results, indent=2, default=str))