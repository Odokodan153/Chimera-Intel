"""
(NEW) HUMINT-to-ARG Fuser Module.

This module provides the missing integration step from the roadmap:
'-> ARG ingestion with provenance & reliability fields.'

It reads from the PostgreSQL database (where HUMINT data is stored) and
fuses the data as nodes and relationships into the central Neo4j
Chimera Intelligence Graph (ARG).
"""

import typer
import psycopg2
from psycopg2.extras import DictCursor
from typing import Dict
from .utils import console
from .database import get_db_connection
from .arg_service import get_arg_service

arg_fuser_app = typer.Typer(
    name="arg-fuser",
    help="Fuses data from modules (like HUMINT) into the central ARG.",
)

def fuse_humint_to_arg() -> Dict[str, int]:
    """
    (NEW) Reads all HUMINT data from PostgreSQL and ingests it into the Neo4j ARG.
    
    This function implements the final step of the HUMINT architecture.
    (Implements: ARG Ingestion)
    
    Returns:
        A dictionary summarizing the number of items fused.
    """
    console.print("Starting HUMINT to ARG fusion...")
    
    pg_conn = None
    arg_service = get_arg_service()
    
    counts = {"sources": 0, "reports": 0, "links": 0}
    
    try:
        # 1. Connect to PostgreSQL (the source)
        pg_conn = get_db_connection()
        cursor = pg_conn.cursor(cursor_factory=DictCursor)
        
        # 2. Fuse HumintSource nodes
        console.print("Fusing HUMINT Sources...")
        cursor.execute("SELECT id, name, reliability, expertise, registered_on FROM humint_sources")
        for record in cursor.fetchall():
            # Use ArgService to create a specific node type
            arg_service.graph.create_node(
                "HumintSource",
                properties={
                    "name": record["name"],
                    "reliability": record["reliability"],
                    "expertise": record["expertise"],
                    "registered_on": record["registered_on"],
                    "postgres_id": record["id"]
                },
                unique_property="name"
            )
            counts["sources"] += 1

        # 3. Fuse HumintReport nodes and link to Sources
        console.print("Fusing HUMINT Reports...")
        cursor.execute(
            """
            SELECT r.id, r.report_type, r.reported_on, r.entities, s.name AS source_name
            FROM humint_reports r
            JOIN humint_sources s ON r.source_id = s.id
            """
        )
        for record in cursor.fetchall():
            report_properties = {
                "postgres_id": record["id"],
                "type": record["report_type"],
                "reported_on": record["reported_on"],
                "entities": record["entities"]
            }
            # Create the report node
            arg_service.graph.create_node(
                "HumintReport",
                properties=report_properties,
                unique_property="postgres_id"
            )
            
            # Link it to its source
            arg_service.graph.create_relationship(
                "HumintSource", record["source_name"], "name",
                "SUBMITTED",
                "HumintReport", record["id"], "postgres_id"
            )
            counts["reports"] += 1
            
        # 4. Fuse Network Links (from humint_network_links AND osint_fusion)
        console.print("Fusing Network Links...")
        cursor.execute("SELECT entity_a, relationship, entity_b, source_report_id FROM humint_network_links")
        for record in cursor.fetchall():
            # Use ArgService helper to create generic entities and relationships
            # This handles the 'auto-link' logic for the graph.
            arg_service.add_relationship(
                node_a_label="Entity",
                node_a_name=record["entity_a"],
                relationship_type=record["relationship"].upper().replace(" ", "_"),
                node_b_label="Entity",
                node_b_name=record["entity_b"],
                provenance=f"HUMINT Report {record['source_report_id'] or 'N/A'}"
            )
            counts["links"] += 1

        console.print(f"[bold green]ARG Fusion Complete.[/bold green]")
        console.print(f"  - Fused {counts['sources']} sources.")
        console.print(f"  - Fused {counts['reports']} reports.")
        console.print(f"  - Fused {counts['links']} network links.")
        
        return counts

    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]PostgreSQL Error during fusion:[/bold red] {e}")
    except Exception as e:
        # This will catch Neo4j connection errors
        console.print(f"[bold red]ARG Error during fusion:[/bold red] {e}")
    finally:
        if pg_conn:
            pg_conn.close()
            
    return counts


# --- CLI Command for this module ---

@arg_fuser_app.command("sync-humint")
def cli_sync_humint():
    """
    (NEW) Reads all data from the HUMINT module (PostgreSQL) and fuses
    it into the Chimera Intelligence Graph (Neo4j).
    """
    fuse_humint_to_arg()