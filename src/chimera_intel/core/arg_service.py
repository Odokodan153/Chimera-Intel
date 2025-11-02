"""
Provides the core services and CLI for the Adversary Research Grid (ARG).

This single module contains:
1.  Pydantic schemas for graph entities and relationships.
2.  The ARGService class for all Neo4j business logic.
3.  The singleton 'arg_service_instance' to run operations.
4.  The Typer 'arg_app' and all associated CLI commands.
"""

import logging
import typer
import json
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from rich.table import Table
from rich.json import JSON

# Reuse the existing Neo4j connection and console
from .graph_db import graph_db_instance
from .utils import console

logger = logging.getLogger(__name__)

# --- 1. Pydantic Schemas for Entity Standardization ---
# These schemas help with identity resolution and data governance (PII)

class BaseEntity(BaseModel):
    """Base model for a graph entity, ensuring consistent properties."""
    id_value: str = Field(..., description="The unique identifying value (e.g., domain name, IP address, email)")
    id_type: str = Field(..., description="The type of the identifier (e.g., 'domain', 'ip', 'email')")
    label: str = Field(..., description="The Neo4j node label (e.g., 'Domain', 'IPAddress', 'Person')")
    properties: Dict[str, Any] = Field(default_factory=dict)
    
    def get_merge_query(self) -> tuple[str, Dict[str, Any]]:
        """Generates Cypher MERGE query for this node."""
        # Use id_type and id_value as the unique key
        merge_key = f"n.{self.id_type}"
        query = f"""
        MERGE (n:{self.label} {{{self.id_type}: $id_value}})
        ON CREATE SET n += $properties, n.created_at = $timestamp
        ON MATCH SET n += $properties, n.updated_at = $timestamp
        RETURN n
        """
        params = {
            "id_value": self.id_value,
            "properties": self.properties,
            "timestamp": datetime.utcnow().isoformat()
        }
        # Add the id_value to the properties dict for the SET operation
        params["properties"][self.id_type] = self.id_value
        return query, params

class Relationship(BaseModel):
    """Model for a graph relationship."""
    source: BaseEntity
    target: BaseEntity
    label: str = Field(..., description="The Neo4j relationship type (e.g., 'RESOLVES_TO')")
    properties: Dict[str, Any] = Field(default_factory=dict)

    def get_merge_query(self) -> tuple[str, Dict[str, Any]]:
        """Generates Cypher MERGE query for this relationship."""
        
        # Define match keys for source and target
        source_key = f"s.{self.source.id_type}"
        target_key = f"t.{self.target.id_type}"

        query = f"""
        MATCH (s:{self.source.label} {{{source_key}: $source_id}})
        MATCH (t:{self.target.label} {{{target_key}: $target_id}})
        MERGE (s)-[r:{self.label}]->(t)
        ON CREATE SET r += $properties, r.created_at = $timestamp
        ON MATCH SET r += $properties, r.updated_at = $timestamp
        RETURN r
        """
        params = {
            "source_id": self.source.id_value,
            "target_id": self.target.id_value,
            "properties": self.properties,
            "timestamp": datetime.utcnow().isoformat()
        }
        return query, params


# --- 2. Core ARG Service Class ---

class ARGService:
    """
    Manages interactions with the global Adversary Research Grid (ARG).
    """
    def __init__(self, db_driver):
        self.db = db_driver
        if not self.db:
            logger.error("ARGService initialized without a valid database driver.")

    def run_arg_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Executes a read-only Cypher query against the ARG.
        """
        if "set" in query.lower() or "create" in query.lower() or "merge" in query.lower() or "delete" in query.lower():
             logger.warning("This method is for read-only queries. Use ingestion methods to write data.")
             # In a real app, you might raise an error here
        
        return self.db.execute_query(query, parameters)

    def ingest_entities_and_relationships(self, entities: List[BaseEntity], relationships: List[Relationship]):
        """
        Ingests a list of entities and relationships into the ARG using MERGE
        for deduplication.
        """
        if not self.db:
            logger.error("Cannot ingest: database driver is not available.")
            return

        node_count = 0
        edge_count = 0
        
        try:
            with self.db._driver.session() as session:
                # Ingest Entities
                for entity in entities:
                    query, params = entity.get_merge_query()
                    session.run(query, params)
                    node_count += 1
                
                # Ingest Relationships
                for rel in relationships:
                    query, params = rel.get_merge_query()
                    session.run(query, params)
                    edge_count += 1
            
            logger.info(f"Successfully ingested {node_count} nodes and {edge_count} edges into ARG.")
            console.print(f"Successfully ingested [bold green]{node_count}[/bold green] nodes and [bold green]{edge_count}[/bold green] edges into ARG.")
        
        except Exception as e:
            logger.error(f"Error during ARG ingestion: {e}")
            console.print(f"[bold red]Error during ARG ingestion:[/bold red] {e}")

    def find_shared_directors(self) -> List[Dict[str, Any]]:
        """
        Example automated pattern search:
        Finds people who are directors of more than one company.
        """
        query = """
        MATCH (p:Person)-[:IS_DIRECTOR_OF]->(c:Company)
        WITH p, count(c) AS companies_directed
        WHERE companies_directed > 1
        MATCH (p)-[:IS_DIRECTOR_OF]->(c:Company)
        RETURN p.name AS person_name, 
               companies_directed, 
               collect(c.name) AS companies
        ORDER BY companies_directed DESC
        LIMIT 25
        """
        return self.run_arg_query(query)

    def find_clusters_wcc(self) -> List[Dict[str, Any]]:
        """
        Example Graph ML (MVP):
        Runs the Weakly Connected Components (WCC) algorithm to find
        disjoint clusters of entities.
        """
        # Note: This requires the GDS (Graph Data Science) library to be
        # installed in Neo4j.
        check_gds = "CALL gds.proc.list() YIELD name WHERE name = 'gds.wcc.stream' RETURN count(*) > 0 AS exists"
        gds_exists = self.run_arg_query(check_gds)
        
        if not gds_exists or not gds_exists[0].get('exists'):
            logger.warning("Neo4j GDS library not found. Cannot run WCC clustering.")
            console.print("[bold yellow]Warning:[/bold yellow] Neo4j GDS library not found. Cannot run WCC clustering.")
            return []

        query = """
        CALL gds.wcc.stream({
          nodeProjection: '*',
          relationshipProjection: '*'
        })
        YIELD nodeId, componentId
        RETURN componentId, 
               count(nodeId) AS cluster_size,
               collect(gds.util.asNode(nodeId).name) AS nodes_in_cluster
        ORDER BY cluster_size DESC
        LIMIT 10
        """
        return self.run_arg_query(query)

    def get_entity_temporal_evolution(self, entity_type: str, entity_id: str) -> List[Dict[str, Any]]:
        """
        Example Temporal Query:
        Finds an entity and its direct relationships, ordered by update time.
        """
        query = f"""
        MATCH (n:{entity_type} {{{entity_type.lower()}: $entity_id}})-[r]-(m)
        RETURN n.name AS entity, 
               type(r) AS relationship_type, 
               m.name AS related_entity, 
               r.updated_at AS last_seen
        WHERE r.updated_at IS NOT NULL
        ORDER BY r.updated_at DESC
        LIMIT 50
        """
        return self.run_arg_query(query, {"entity_id": entity_id})


# --- 3. Singleton instance of the ARG service ---
arg_service_instance = ARGService(graph_db_instance)


# --- 4. Typer CLI Application ---

arg_app = typer.Typer(
    help="Adversary Research Grid (ARG) - Global Correlation Graph."
)

@arg_app.command("query")
def query_arg(
    cypher: str = typer.Argument(..., help="The raw Cypher query to execute.")
):
    """
    Run a direct, read-only Cypher query against the ARG.
    """
    console.print(f"[cyan]Executing query:[/cyan] [dim]{cypher}[/dim]")
    results = arg_service_instance.run_arg_query(cypher)
    
    if not results:
        console.print("[yellow]Query returned no results.[/yellow]")
        return

    # Pretty print results in a table
    table = Table(show_header=True, header_style="bold magenta")
    headers = results[0].keys()
    for header in headers:
        table.add_column(header)
    
    for row in results:
        str_row = []
        for item in row.values():
            if isinstance(item, (dict, list)):
                str_row.append(JSON.from_data(item))
            else:
                str_row.append(str(item))
        table.add_row(*str_row)
        
    console.print(table)


@arg_app.command("ingest_example")
def ingest_example_data():
    """
    Ingests a small set of example data into the ARG.
    """
    console.print("[cyan]Ingesting example data into ARG...[/cyan]")
    
    # Define example entities
    p1 = BaseEntity(id_value="john.doe@example.com", id_type="email", label="Person", properties={"name": "John Doe"})
    p2 = BaseEntity(id_value="jane.smith@example.com", id_type="email", label="Person", properties={"name": "Jane Smith"})
    
    c1 = BaseEntity(id_value="shellco-a.com", id_type="domain", label="Company", properties={"name": "ShellCo A"})
    c2 = BaseEntity(id_value="shellco-b.com", id_type="domain", label="Company", properties={"name": "ShellCo B"})
    
    ip1 = BaseEntity(id_value="198.51.100.1", id_type="ip", label="IPAddress", properties={"asn": "AS12345"})
    
    entities = [p1, p2, c1, c2, ip1]
    
    # Define relationships
    rels = [
        Relationship(source=p1, target=c1, label="IS_DIRECTOR_OF"),
        Relationship(source=p1, target=c2, label="IS_DIRECTOR_OF"), # Shared director
        Relationship(source=p2, target=c2, label="IS_DIRECTOR_OF"),
        Relationship(source=c1, target=ip1, label="RESOLVES_TO", properties={"record_type": "A"}),
        Relationship(source=c2, target=ip1, label="RESOLVES_TO", properties={"record_type": "A"}), # Shared IP
    ]
    
    arg_service_instance.ingest_entities_and_relationships(entities, rels)


@arg_app.command("find-pattern")
def find_patterns(
    pattern: str = typer.Argument("shared_directors", help="Name of the pattern to find (e.g., 'shared_directors').")
):
    """
    Run pre-defined automated pattern searches.
    """
    console.print(f"[cyan]Running pattern search:[/cyan] [bold]{pattern}[/bold]")
    if pattern == "shared_directors":
        results = arg_service_instance.find_shared_directors()
    else:
        console.print(f"[red]Error:[/red] Unknown pattern '{pattern}'.")
        raise typer.Exit(code=1)
        
    # Print results (using the same table logic as 'query' command)
    if not results:
        console.print("[yellow]Pattern search returned no results.[/yellow]")
        return
    
    table = Table(show_header=True, header_style="bold magenta")
    headers = results[0].keys()
    for header in headers:
        table.add_column(header)
    for row in results:
        table.add_row(*[str(v) for v in row.values()])
    console.print(table)


@arg_app.command("find-clusters")
def find_clusters():
    """
    Run Graph ML clustering (WCC) to find disjoint subgraphs.
    (Requires Neo4j GDS Library)
    """
    console.print("[cyan]Running WCC clustering...[/cyan]")
    results = arg_service_instance.find_clusters_wcc()
    
    if not results:
        console.print("[yellow]Clustering algorithm returned no results.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    headers = results[0].keys()
    for header in headers:
        table.add_column(header)
    for row in results:
        str_row = []
        for item in row.values():
            if isinstance(item, (dict, list)):
                str_row.append(JSON.from_data(item))
            else:
                str_row.append(str(item))
        table.add_row(*str_row)
    
    console.print(table)


@arg_app.command("temporal-query")
def temporal_query(
    entity_type: str = typer.Argument(..., help="Node label, e.g., 'Company'"),
    entity_id: str = typer.Argument(..., help="Unique ID, e.g., 'shellco-a.com'")
):
    """
    Follow an entity's evolution over time based on relationship updates.
    """
    console.print(f"[cyan]Getting temporal data for {entity_type}:[/cyan] [bold]{entity_id}[/bold]")
    results = arg_service_instance.get_entity_temporal_evolution(entity_type, entity_id)

    if not results:
        console.print("[yellow]Temporal query returned no results.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    headers = results[0].keys()
    for header in headers:
        table.add_column(header)
    for row in results:
        table.add_row(*[str(v) for v in row.values()])
    console.print(table)