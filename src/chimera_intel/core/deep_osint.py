"""
DarkSocialMonitor tracks content in private platforms like Telegram and Discord given keywords and channel lists, returning a dictionary of found snippets. 
IoTDeviceScanner searches Shodan for exposed IoT devices using a query string and returns a list of device details. 
DeepGraphAnalyzer analyzes a graph from GraphDB to find indirect relationships or partnership networks, returning paths or connected entities.
"""
import logging
from typing import List, Dict, Any, Set
import networkx as nx
from chimera_intel.core.graph_db import GraphDB  
from chimera_intel.core.plugin_interface import ChimeraPlugin
import asyncio  
import shodan  
from .config_loader import API_KEYS  
from .connect import _scrape_telegram, _scrape_discord  

logging.basicConfig(level=logging.INFO)  
logger = logging.getLogger(__name__)  


class DarkSocialMonitor(ChimeraPlugin):
    """
    Monitors and tracks content shared in private or semi-private
    digital communities (e.g., Telegram, Discord, Reddit).
    """
    plugin_name = "dark_social_monitor"

    def __init__(self):
        # Clients are no longer needed here as we use asyncio.run with imported functions
        logger.info("DarkSocialMonitor initialized.")  # <-- Use logger

    def track_content(self, keywords: List[str], telegram_channels: List[str], discord_channels: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Searches configured dark social platforms for given keywords.

        Args:
            keywords: A list of keywords to search for.
            telegram_channels: List of Telegram channel usernames.
            discord_channels: List of Discord channel IDs.

        Returns:
            A dictionary where keys are platform names and values are
            lists of found content snippets.
        """
        results = {"telegram": [], "discord": []}
        
        # This is a sync function, so we must use asyncio.run()
        # to call our async scraping functions from connect.py
        
        # Note: The _scrape_telegram/discord functions search
        # for a single target, not a list of keywords. We'll adapt by searching
        # for the *first* keyword as a demonstration.
        
        target_keyword = keywords[0] if keywords else ""
        if not target_keyword:
            return results

        try:
            logger.info(f"Running Telegram scrape for: {target_keyword}")
            # This will be slow as it spins up a new event loop
            telegram_results = asyncio.run(_scrape_telegram(target_keyword, telegram_channels))
            if telegram_results:
                results["telegram"] = telegram_results
        except Exception as e:
            logger.error(f"Failed to track content on Telegram: {e}")

        try:
            logger.info(f"Running Discord scrape for: {target_keyword}")
            discord_results = asyncio.run(_scrape_discord(target_keyword, discord_channels))
            if discord_results:
                results["discord"] = discord_results
        except Exception as e:
            logger.error(f"Failed to track content on Discord: {e}")
        
        return results

    def run(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        data = {
            "keywords": ["keyword1", "keyword2"],
            "telegram_channels": ["channel_user_name1"],
            "discord_channels": ["1234567890"]
        }
        """
        keywords = data.get("keywords", [])
        telegram_channels = data.get("telegram_channels", [])
        discord_channels = data.get("discord_channels", [])
        
        if not keywords:
            return {"status": "error", "message": "No keywords provided."}
        if not telegram_channels and not discord_channels:
            return {"status": "error", "message": "No channels (telegram_channels or discord_channels) provided."}
        
        results = self.track_content(keywords, telegram_channels, discord_channels)
        return {"status": "success", "data": results}


class IoTDeviceScanner(ChimeraPlugin):
    """
    Discovers and assesses Internet-facing IoT devices using
    integration with search engines like Shodan or Censys.
    """
    plugin_name = "iot_device_scanner"

    def __init__(self):
        # In a real app, load this from config
        self.api_key = API_KEYS.shodan_api_key
        if not self.api_key:
            logger.error("SHODAN_API_KEY not found. IoTDeviceScanner will not work.")
            self.client = None
        else:
            self.client = shodan.Shodan(self.api_key)  # <-- REAL CLIENT
            logger.info("IoTDeviceScanner initialized with real Shodan client.")

    def discover_devices(self, query: str) -> List[Dict[str, Any]]:
        """
        Searches for exposed devices based on a query string.

        Args:
            query: A search query (e.g., 'org:"Example Corp"', 'product:"webcam"', 'port:502').

        Returns:
            A list of found devices with enriched data.
        """
        if not self.client:
            return []
            
        try:
            results = self.client.search(query, limit=100)
            
            # Re-format Shodan results to match the simple mock output
            devices = [
                {
                    "ip_str": res.get("ip_str"),
                    "port": res.get("port"),
                    "org": res.get("org"),
                    "data": res.get("data", "").strip(),
                    "hostnames": res.get("hostnames", []),
                    "asn": res.get("asn"),
                }
                for res in results.get("matches", [])
            ]
            return devices
            
        except shodan.APIError as e:
            logger.error(f"Failed to discover IoT devices (Shodan APIError): {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to discover IoT devices: {e}")
            return []

    def run(self, data: Dict[str, Any]) -> Dict[str, Any]:
        query = data.get("query")
        if not query:
            return {"status": "error", "message": "No query provided."}
        
        if not self.client:
             return {"status": "error", "message": "Shodan API key not configured."}
        
        devices = self.discover_devices(query)
        return {"status": "success", "data": {"devices": devices, "count": len(devices)}}


class DeepGraphAnalyzer(ChimeraPlugin):
    """
    Performs deep graph analysis to find indirect and non-obvious
    relationships between entities.

    Integrates with the existing GraphDB.
    """
    plugin_name = "deep_graph_analyzer"

    def __init__(self, graph_db: GraphDB):
        self.graph_db = graph_db
        # Get the NetworkX graph object from the GraphDB
        self.graph = self.graph_db.get_nx_graph() 
        logger.info("DeepGraphAnalyzer initialized.")

    def find_indirect_relationships(self, start_node: str, end_node: str, max_depth: int = 3) -> List[List[str]]:
        """
        Finds all paths between two nodes up to a certain depth.

        Args:
            start_node: The name/ID of the starting entity.
            end_node: The name/ID of the target entity.
            max_depth: The maximum number of hops (nodes) in a path.

        Returns:
            A list of paths, where each path is a list of node names.
        """
        if not self.graph:
            logger.warning("Graph is not loaded. Cannot perform analysis.")
            return []

        if start_node not in self.graph or end_node not in self.graph:
            logger.warning(f"Nodes {start_node} or {end_node} not in graph.")
            return []
            
        try:
            # Use networkx to find all simple paths up to a certain cutoff
            paths = list(nx.all_simple_paths(
                self.graph, 
                source=start_node, 
                target=end_node, 
                cutoff=max_depth
            ))
            
            # Filter out direct relationships (path length 2: [node1, node2])
            indirect_paths = [path for path in paths if len(path) > 2]
            return indirect_paths
        except Exception as e:
            logger.error(f"Error finding indirect paths: {e}")
            return []

    def find_all_partnerships(self, company_node: str, relationship_type: str = "PARTNER_OF", depth: int = 2) -> Set[str]:
        """
        Finds partners, and partners-of-partners (subsidiaries, contractors, etc.).

        Args:
            company_node: The starting company node name/ID.
            relationship_type: The edge type to follow (e.g., "PARTNER_OF", "CONTRACTOR_FOR").
            depth: How many levels to traverse.

        Returns:
            A set of unique entity names connected via the specified relationship.
        """
        if not self.graph:
            logger.warning("Graph is not loaded for partnership analysis.")
            return set()
            
        if company_node not in self.graph:
            return set()

        # Use breadth-first search (BFS) to find neighbors
        bfs_edges = nx.bfs_edges(self.graph, source=company_node, depth_limit=depth)
        
        connected_nodes = set()
        for u, v in bfs_edges:
            # Check if the edge relationship type matches
            edge_data = self.graph.get_edge_data(u, v)
            
            # This logic assumes relationship type is stored in an 'relation' attribute
            # Adjust as per your graph schema in graph_db.py
            if edge_data and edge_data.get("relation") == relationship_type:
                connected_nodes.add(v)
        
        return connected_nodes

    def run(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs analysis based on the provided 'task'.
        
        Tasks:
        - 'find_indirect_paths': Requires 'start_node', 'end_node', 'max_depth'
        - 'find_partners': Requires 'company_node', 'relationship_type', 'depth'
        """
        task = data.get("task")
        
        # Ensure graph is loaded before running tasks
        if not self.graph:
             self.graph = self.graph_db.get_nx_graph()
             if not self.graph:
                 return {"status": "error", "message": "GraphDB is not available or empty."}
                 
        if task == "find_indirect_paths":
            results = self.find_indirect_relationships(
                start_node=data.get("start_node"),
                end_node=data.get("end_node"),
                max_depth=data.get("max_depth", 3)
            )
            return {"status": "success", "task": task, "paths": results}
        
        elif task == "find_partners":
            results = self.find_all_partnerships(
                company_node=data.get("company_node"),
                relationship_type=data.get("relationship_type", "PARTNER_OF"),
                depth=data.get("depth", 2)
            )
            return {"status": "success", "task": task, "entities": list(results)}
            
        else:
            return {"status": "error", "message": "Invalid task provided."}