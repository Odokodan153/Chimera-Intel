"""
MLint Graph Analyzer
(Updated with high-performance batch inserts)
"""
import logging
from typing import List, Dict, Any
from neo4j import AsyncGraphDatabase, AsyncDriver

# These modules are assumed to be in the same directory
from .mlint_config import settings
from .schemas import Transaction, GnnAnomalyResult

log = logging.getLogger(__name__)

class GraphAnalyzer:
    """
    Handles all interactions with the Neo4j graph database.
    """
    _driver: AsyncDriver = None

    def __init__(self):
        # Initialize driver if it doesn't exist or is closed
        if not self._driver or self._driver.closed():
            try:
                self._driver = AsyncGraphDatabase.driver(
                    settings.neo4j_uri, 
                    auth=(settings.neo4j_user, settings.neo4j_password)
                )
                log.info(f"Neo4j driver initialized for {settings.neo4j_uri}")
                GraphAnalyzer._driver = self._driver # Store as class variable
            except Exception as e:
                log.critical(f"Failed to initialize Neo4j driver: {e}", exc_info=True)
                raise

    async def close(self):
        """Closes the Neo4j driver connection."""
        if self._driver and not self._driver.closed():
            await self._driver.close()
            log.info("Neo4j driver closed.")
            GraphAnalyzer._driver = None # Clear static driver

    async def add_transaction_to_graph(self, tx: Transaction):
        """ (DEPRECATED) Persists a single transaction. Use batch instead. """
        await self.add_transactions_batch([tx])
    
    # --- Task 3: New Batch Insert Function ---
    async def add_transactions_batch(self, txs: List[Transaction]):
        """
        Persists a batch of transactions to the graph using UNWIND.
        This is 10-100x faster than single inserts.
        """
        if not txs:
            return

        query = """
        UNWIND $txs_batch as tx // <-- Unwind the batch
        
        // Merge sender and receiver
        MERGE (s:Entity {id: tx.from_entity})
        ON CREATE SET s.type = tx.from_type
        MERGE (r:Entity {id: tx.to_entity})
        ON CREATE SET r.type = tx.to_type
        
        // Merge the relationship
        MERGE (s)-[t:TRANSACTED_WITH]->(r)
        ON CREATE SET 
            t.tx_id_list = [tx.tx_id], // Start a list of tx IDs
            t.amount = tx.amount,
            t.currency = tx.currency,
            t.first_seen = tx.timestamp,
            t.last_seen = tx.timestamp,
            t.count = 1
        ON MATCH SET
            t.count = t.count + 1,
            t.amount = t.amount + tx.amount,
            t.last_seen = tx.timestamp,
            t.tx_id_list = t.tx_id_list + tx.tx_id 
        """
        
        # Convert Transaction objects to parameter dictionaries
        txs_batch_params = []
        for tx in txs:
            txs_batch_params.append({
                "from_entity": tx.from_entity,
                "from_type": tx.from_entity.split(":")[0] if ":" in tx.from_entity else "Unknown",
                "to_entity": tx.to_entity,
                "to_type": tx.to_entity.split(":")[0] if ":" in tx.to_entity else "Unknown",
                "tx_id": tx.tx_id,
                "amount": tx.amount,
                "currency": tx.currency,
                "timestamp": tx.timestamp.isoformat()
            })

        try:
            async with self._driver.session() as session:
                await session.run(query, {"txs_batch": txs_batch_params})
            log.info(f"Added batch of {len(txs)} transactions to graph.")
        except Exception as e:
            log.error(f"Failed to add transaction batch to graph: {e}", exc_info=True)
    # --- End Task 3 ---

    async def analyze_entity_graph(self, entity_id: str) -> Dict[str, Any]:
        """
        Gets basic graph metrics for a single entity (e.g., degree).
        """
        query = """
        MATCH (e:Entity {id: $entity_id})
        RETURN 
            size((e)-->()) as out_degree,
            size((e)<--()) as in_degree,
            size((e)--()) as total_degree
        """
        try:
            async with self._driver.session() as session:
                result = await session.run(query, {"entity_id": entity_id})
                record = await result.single()
                if record:
                    return record.data()
                return {"error": "Entity not found in graph."}
        except Exception as e:
            log.error(f"Failed to analyze entity graph for {entity_id}: {e}", exc_info=True)
            return {"error": str(e)}

    async def run_pagerank_anomaly(self) -> List[GnnAnomalyResult]:
        """
        Executes PageRank on the graph to find anomalous (overly central)
        entities. This is a functional substitute for a GNN.
        
        NOTE: Requires the Neo4j GDS (Graph Data Science) plugin.
        """
        log.info("Running PageRank anomaly detection...")
        
        graph_name = 'entity-transactions'
        
        # 2. Project the graph in memory for GDS
        project_query = f"""
        CALL gds.graph.project(
            '{graph_name}',
            'Entity',
            'TRANSACTED_WITH',
            {{
                relationshipProperties: 'amount'
            }}
        )
        """
        
        # 3. Run PageRank
        pagerank_query = f"""
        CALL gds.pageRank.stream('{graph_name}', {{
            relationshipWeightProperty: 'amount'
        }})
        YIELD nodeId, score
        RETURN gds.util.asNode(nodeId).id AS entityId, 
               gds.util.asNode(nodeId).type AS entityType, 
               score
        ORDER BY score DESC
        LIMIT 10 
        """
        
        # 4. Drop the projection to free memory
        drop_query = f"CALL gds.graph.drop('{graph_name}')"
        
        results = []
        try:
            async with self._driver.session() as session:
                # Always drop graph first in case of a stale one
                try:
                    await session.run(drop_query)
                except Exception:
                    pass # Ignore if graph doesn't exist
                
                # Create and run
                await session.run(project_query)
                pagerank_results = await session.run(pagerank_query)
                
                async for record in pagerank_results:
                    results.append(GnnAnomalyResult(
                        node_id=record["entityId"],
                        node_type=record["entityType"],
                        score=record["score"],
                        reason=f"High PageRank score ({record['score']:.4f})"
                    ))
                
                # Clean up
                await session.run(drop_query)
                
            log.info(f"PageRank complete. Found {len(results)} anomalous nodes.")
            return results
            
        except Exception as e:
            log.error(f"Failed to run PageRank anomaly detection: {e}", exc_info=True)
            if "Unknown procedure" in str(e):
                log.critical("Neo4j GDS (Graph Data Science) plugin not found. PageRank cannot run.")
                return [GnnAnomalyResult(node_id="error", node_type="system", score=0, reason="GDS Plugin not installed.")]
            return []