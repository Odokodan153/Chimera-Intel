"""
Core module for connecting to and interacting with the Neo4j Graph Database.
This acts as the central brain for all interconnected intelligence data.
"""

import logging
from neo4j import GraphDatabase
from chimera_intel.core.config_loader import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

logger = logging.getLogger(__name__)


class GraphDB:
    """A singleton class to manage the Neo4j database connection."""

    _instance = None
    _driver = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GraphDB, cls).__new__(cls)
            try:
                cls._driver = GraphDatabase.driver(
                    NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)
                )
                logger.info("Neo4j driver initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize Neo4j driver: {e}")
                cls._driver = None
        return cls._instance

    def close(self):
        """Closes the Neo4j database driver connection."""
        if self._driver is not None:
            self._driver.close()
            logger.info("Neo4j driver closed.")

    def execute_query(self, query: str, parameters: dict = None):
        """
        Executes a Cypher query against the graph database.

        Args:
            query (str): The Cypher query to execute.
            parameters (dict, optional): Parameters to pass to the query.
        """
        if self._driver is None:
            logger.error("Cannot execute query, Neo4j driver is not available.")
            return
        try:
            with self._driver.session() as session:
                session.run(query, parameters or {})
        except Exception as e:
            logger.error(f"Error executing Cypher query '{query}': {e}")

    def add_node(self, label: str, properties: dict):
        """
        Adds or updates a node in the graph using MERGE to avoid duplicates.
        A 'name' or 'id' property is recommended for merging.
        """
        if "name" not in properties and "id" not in properties:
            logger.warning(
                f"Node of type '{label}' added without a unique property ('name' or 'id'). This may create duplicate nodes."
            )
        # Build the MERGE query dynamically based on a unique identifier

        unique_property = "name" if "name" in properties else "id"

        query = (
            f"MERGE (n:{label} {{{unique_property}: $unique_val}}) "
            "ON CREATE SET n = $props "
            "ON MATCH SET n += $props"
        )
        params = {"unique_val": properties.get(unique_property), "props": properties}
        self.execute_query(query, params)

    def add_relationship(
        self,
        from_node_label: str,
        from_node_id: str,
        relationship_type: str,
        to_node_label: str,
        to_node_id: str,
    ):
        """
        Creates a relationship between two existing nodes.
        """
        query = (
            f"MATCH (a:{from_node_label} {{name: $from_id}}), (b:{to_node_label} {{name: $to_id}}) "
            f"MERGE (a)-[r:{relationship_type}]->(b)"
        )
        self.execute_query(query, {"from_id": from_node_id, "to_id": to_node_id})


# Initialize a singleton instance for use across the application

graph_db_instance = GraphDB()
