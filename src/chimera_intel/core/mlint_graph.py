"""
MLINT Graph module.
Contains all Neo4j logic for graph analysis, cycle detection,
GNN anomaly scoring, and entity persistence.
"""

import logging
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from neo4j import GraphDatabase, Driver
from typing import Optional, List, Any

# Core project imports
from chimera_intel.core.schemas import (
    GnnAnomalyResult,
    UboResult,
    Transaction
)
from chimera_intel.core.config_loader import API_KEYS

logger = logging.getLogger(__name__)

# --- [MLINT 2.0] Helper: Neo4j Driver Context ---

def get_neo4j_driver() -> Optional[Driver]:
    """Initializes and returns a Neo4j driver instance."""
    uri, user, password = API_KEYS.neo4j_uri, API_KEYS.neo4j_user, API_KEYS.neo4j_password
    if not all([uri, user, password]):
        logger.error("Neo4j credentials not set. Cannot connect to graph.")
        return None
    try:
        return GraphDatabase.driver(uri, auth=(user, password))
    except Exception as e:
        logger.error(f"Failed to create Neo4j driver: {e}", exc_info=True)
        return None

# --- Graph Writing Functions ---

def insert_transaction_to_neo4j(driver: Driver, tx: Transaction):
    """
    [MLINT 2.0] Helper function to insert a single transaction into Neo4j
    in a real-time, idempotent way using MERGE.
    """
    cypher_query = """
    MERGE (sender:Account {id: $sender_id})
    ON CREATE SET sender.jurisdiction = $sender_jurisdiction
    MERGE (receiver:Account {id: $receiver_id})
    ON CREATE SET receiver.jurisdiction = $receiver_jurisdiction
    
    MERGE (sender)-[r:SENT_TO {id: $tx_id}]->(receiver)
    ON CREATE SET
        r.amount = $amount,
        r.currency = $currency,
        r.date = $date
    """
    try:
        with driver.session() as session:
            session.run(
                cypher_query,
                tx_id=tx.id,
                sender_id=tx.sender_id,
                sender_jurisdiction=tx.sender_jurisdiction,
                receiver_id=tx.receiver_id,
                receiver_jurisdiction=tx.receiver_jurisdiction,
                amount=tx.amount,
                currency=tx.currency,
                date=tx.date.isoformat()
            )
        logger.info(f"Inserted TX {tx.id} into Neo4j.")
    except Exception as e:
        logger.error(f"Failed to insert TX {tx.id} into Neo4j: {e}", exc_info=True)

def update_graph_entities(driver: Driver, ubo_result: UboResult):
    """
    [MLINT 2.0] Updates the graph with Company and Person nodes from a UBO result.
    """
    if not ubo_result or ubo_result.error or not ubo_result.ultimate_beneficial_owners:
        return

    company_name = ubo_result.company_name
    
    # Create the company node
    cypher_merge_company = "MERGE (c:Company {name: $company_name})"
    
    with driver.session() as session:
        session.run(cypher_merge_company, company_name=company_name)
        
        # Loop and link UBOs
        for owner in ubo_result.ultimate_beneficial_owners:
            if owner.name == "No UBO data found":
                continue
                
            cypher_merge_ubo = """
            MERGE (c:Company {name: $company_name})
            MERGE (p:Person {name: $owner_name})
            MERGE (c)-[r:HAS_UBO]->(p)
            ON CREATE SET
                r.ownership_percentage = $ownership,
                p.is_pep = $is_pep
            ON MATCH SET
                r.ownership_percentage = $ownership,
                p.is_pep = $is_pep
            """
            session.run(
                cypher_merge_ubo,
                company_name=company_name,
                owner_name=owner.name,
                ownership=owner.ownership_percentage,
                is_pep=owner.is_pep
            )
        logger.info(f"Updated graph with UBO data for {company_name}")

def link_wallet_to_person(driver: Driver, wallet_address: str, person_name: str):
    """
    [MLINT 2.0] Links a Wallet (or Account) node to a Person node.
    """
    cypher_query = """
    MERGE (w:Wallet {id: $wallet_address})
    MERGE (p:Person {name: $person_name})
    MERGE (p)-[r:OWNS_WALLET]->(w)
    """
    try:
        with driver.session() as session:
            session.run(cypher_query, wallet_address=wallet_address, person_name=person_name)
        logger.info(f"Linked wallet {wallet_address} to person {person_name} in graph.")
    except Exception as e:
        logger.error(f"Failed to link wallet in graph: {e}", exc_info=True)

# --- Graph Reading Functions ---

def run_neo4j_cycle_detection(driver: Driver, max_length: int = 5) -> List[List[str]]:
    """
    Finds transaction cycles (round-tripping) using Neo4j.
    """
    cypher_query = f"""
    MATCH path = (a:Account)-[:SENT_TO*1..{max_length}]->(a)
    WHERE all(n IN nodes(path) | size([m IN nodes(path) WHERE m = n]) = 1)
    RETURN [n IN nodes(path) | n.id] as cycle, length(path) as length
    ORDER BY length
    LIMIT 100
    """
    with driver.session() as session:
        result = session.run(cypher_query)
        cycles = [record["cycle"] for record in result]
    return cycles

def detect_graph_anomalies(driver: Driver) -> List[GnnAnomalyResult]:
    """
    [MLINT 2.0] REAL GNN/Graph Anomaly Detection Function.
    Runs IsolationForest on graph features (PageRank, Community) from Neo4j.
    """
    logger.info("Running graph feature-based anomaly detection...")
    
    # This query assumes PageRank/Community are pre-calculated
    # (e.g., by a nightly GDS job)
    cypher_query = """
    MATCH (a:Account)
    WHERE a.pagerank IS NOT NULL AND a.community IS NOT NULL
    RETURN a.id as entity_id, a.pagerank as pagerank, a.community as community,
           a.total_in_amount as total_in, a.total_out_amount as total_out
    """
    
    results = []
    try:
        with driver.session() as session:
            data = session.run(cypher_query)
            df = pd.DataFrame([dict(record) for record in data])
        
        if df.empty:
            logger.warning("No accounts with graph features (pagerank, community) found in Neo4j. Skipping GNN.")
            return []

        features = ['pagerank', 'community', 'total_in', 'total_out']
        df_features = df[features].fillna(0)
        
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(df_features)
        
        model = IsolationForest(contamination=0.02, random_state=42).fit(features_scaled)
        df['anomaly_score_raw'] = model.decision_function(features_scaled)
        df['is_anomaly'] = model.predict(features_scaled)

        anomaly_df = df[df['is_anomaly'] == -1].sort_values(by='anomaly_score_raw')

        for _, row in anomaly_df.iterrows():
            reason = f"Anomaly score: {row['anomaly_score_raw']:.3f}. (PageRank: {row['pagerank']:.3f}, Community: {row['community']})"
            results.append(GnnAnomalyResult(
                entity_id=row['entity_id'],
                anomaly_score=(1 - row['anomaly_score_raw']), # Normalize
                reason=[reason]
            ))
        return results
        
    except Exception as e:
        logger.error(f"Failed to run graph anomaly detection: {e}", exc_info=True)
        return [GnnAnomalyResult(error=f"Neo4j query error: {e}")]