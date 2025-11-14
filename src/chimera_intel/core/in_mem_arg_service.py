"""
In-Memory ARG Service using NetworkX.

Provides the same interface as the real ARGService but uses
a NetworkX graph in memory, requiring no external Neo4j database.
"""
import networkx as nx
import logging
from typing import List
from datetime import datetime
from .arg_service import BaseEntity, Relationship 

logger = logging.getLogger(__name__)

class InMemARGService:
    """A 'real' in-memory graph service using NetworkX."""
    
    def __init__(self, db_driver=None): # Accept db_driver to match signature
        self.G = nx.DiGraph() # Initialize an in-memory directed graph
        logger.info("Initialized In-Memory ARG Service (NetworkX)")

    def ingest_entities_and_relationships(
        self, 
        entities: List[BaseEntity], 
        relationships: List[Relationship]
    ):
        """
        Ingests entities and relationships into the in-memory graph.
        This matches the real ARGService method signature.
        """
        node_count = 0
        edge_count = 0
        timestamp = datetime.utcnow().isoformat()

        # Ingest Entities (Nodes) - This mimics MERGE
        for entity in entities:
            node_id = entity.id_value
            # Combine base properties with ID and type
            node_props = {
                **entity.properties,
                entity.id_type: entity.id_value,
                "label": entity.label,
                "updated_at": timestamp,
            }
            
            if not self.G.has_node(node_id):
                node_props["created_at"] = timestamp
                self.G.add_node(node_id, **node_props)
                node_count += 1
            else:
                # Update existing node properties (like MERGE ON MATCH)
                self.G.nodes[node_id].update(node_props)

        # Ingest Relationships (Edges) - This mimics MERGE
        for rel in relationships:
            source_id = rel.source.id_value
            target_id = rel.target.id_value
            
            rel_props = {
                **rel.properties,
                "label": rel.label,
                "updated_at": timestamp,
            }
            
            if not self.G.has_edge(source_id, target_id):
                rel_props["created_at"] = timestamp
                self.G.add_edge(source_id, target_id, **rel_props)
                edge_count += 1
            else:
                # Update existing edge properties
                self.G.edges[source_id, target_id].update(rel_props)
        
        logger.info(f"InMemARG: Ingested {node_count} new nodes and {edge_count} new edges.")
        logger.info(f"InMemARG: Graph now has {self.G.number_of_nodes()} nodes and {self.G.number_of_edges()} edges.")


# Create a singleton instance to be imported
in_mem_arg_service_instance = InMemARGService()