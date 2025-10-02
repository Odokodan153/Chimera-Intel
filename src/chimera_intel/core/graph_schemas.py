from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class GraphNode(BaseModel):
    """Model for a single node in an intelligence graph."""

    id: str  # e.g., "megacorp.com", "1.2.3.4"
    node_type: str  # e.g., "Domain", "IP Address", "Company", "Email"
    label: str
    properties: Dict[str, Any] = {}


class GraphEdge(BaseModel):
    """Model for a relationship (edge) between two nodes in the graph."""

    source: str  # ID of the source node
    target: str  # ID of the target node
    label: str  # e.g., "Resolves To", "Registered By", "Uses Technology"
    properties: Dict[str, Any] = {}


class EntityGraphResult(BaseModel):
    """The main, top-level result model for an entity reconciliation and graph build process."""

    target: str
    total_nodes: int
    total_edges: int
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    error: Optional[str] = None


class GraphNarrativeResult(BaseModel):
    narrative_text: str
    error: Optional[str] = None
