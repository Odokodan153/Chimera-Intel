"""
MLINT Analysis module.
Contains core, non-graph, non-streaming business logic for AML analysis.
- Entity Risk (UBO, PEP, Sanctions)
- Crypto Wallet Screening
- Batch Transaction Analysis
- STIX Reporting
"""

import logging
from .schemas import AMLAlert
import httpx
from neo4j import Driver
import dask.dataframe as dd
import pandas as pd
from datetime import datetime, timedelta
import networkx as nx
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from pyvis.network import Network
from stix2 import Indicator, Identity, Relationship, Bundle
from typing import Optional, List, Dict

# Core project imports
from chimera_intel.core.schemas import (
    JurisdictionRisk,
    EntityRiskResult,
    CryptoWalletScreenResult,
    Transaction,
    TransactionAnalysisResult,
    UboResult,
    UboData,
)
from chimera_intel.core.config_loader import (
    API_KEYS, MLINT_RISK_WEIGHTS, MLINT_AML_API_URL, MLINT_CHAIN_API_URL
)

# MLINT package imports (updated to prefixed, flat structure)
from .mlint_graph import get_neo4j_driver, update_graph_entities

logger = logging.getLogger(__name__)

# --- Risk Data ---
FATF_BLACK_LIST = {"NORTH KOREA", "IRAN", "MYANMAR"}
FATF_GREY_LIST = {
    "PANAMA", "CAYMAN ISLANDS", "TURKEY", "UNITED ARAB EMIRATES", "BARBADOS",
    "GIBRALTAR", "JAMAICA", "NIGERIA", "SOUTH AFRICA", "SYRIA", "YEMEN",
}

# --- Core Functions ---

def get_jurisdiction_risk(country: str) -> JurisdictionRisk:
    """
    Assesses the money laundering risk of a given jurisdiction.
    """
    country_upper = str(country).upper()
    if country_upper in FATF_BLACK_LIST:
        return JurisdictionRisk(
            country=country, risk_level="High", is_fatf_black_list=True,
            risk_score=90, details="FATF Black List (High-Risk Jurisdiction)"
        )
    if country_upper in FATF_GREY_LIST:
        return JurisdictionRisk(
            country=country, risk_level="Medium", is_fatf_grey_list=True,
            risk_score=60, details="FATF Grey List (Jurisdiction Under Increased Monitoring)"
        )
    return JurisdictionRisk(
        country=country, risk_level="Low",
        risk_score=10, details="Not currently on FATF high-risk lists."
    )

async def get_ubo_data(company_name: str) -> UboResult:
    """
    Fetches Ultimate Beneficial Ownership (UBO) data.
    """
    api_key = API_KEYS.open_corporates_api_key or API_KEYS.world_check_api_key
    if not api_key:
        return UboResult(company_name=company_name, error="No UBO API key (e.g., OPEN_CORPORATES_API_KEY) found.")
    
    logger.info(f"Fetching UBO data for {company_name}")
    
    if not MLINT_AML_API_URL:
         return UboResult(company_name=company_name, error="MLINT_AML_API_URL (used as placeholder UBO API) not found.")

    headers = {"Authorization": f"Bearer {api_key}"}
    params = {"companyName": company_name, "queryContext": "ubo"} 

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(MLINT_AML_API_URL, params=params, headers=headers, timeout=30.0)
            response.raise_for_status()
            data = response.json()
        
        owners = []
        for owner_data in data.get("ultimate_beneficial_owners", []):
            owners.append(UboData(
                name=owner_data.get("name", "Unknown"),
                ownership_percentage=owner_data.get("ownership_percentage", 0.0),
                is_pep=owner_data.get("is_pep", False),
                details=owner_data.get("details", "")
            ))
        
        if not owners:
             logger.warning(f"No UBO data returned from API for {company_name}")
             owners.append(UboData(name="No UBO data found", ownership_percentage=0.0))
        
        # [MLINT 2.0] Update graph with UBO data
        ubo_result = UboResult(
            company_name=company_name,
            ultimate_beneficial_owners=owners,
            corporate_structure=data.get("corporate_structure", {})
        )
        
        driver = get_neo4j_driver()
        if driver:
            try:
                update_graph_entities(driver, ubo_result)
            except Exception as e:
                logger.error(f"Failed to update graph with UBO data: {e}", exc_info=True)
            finally:
                driver.close()
        
        return ubo_result
        
    except httpx.RequestError as e:
        logger.error(f"HTTP request failed for UBO data {company_name}: {e}", exc_info=True)
        return UboResult(company_name=company_name, error=f"API request error: {e}")
    except Exception as e:
        logger.error(f"Failed to fetch UBO data for {company_name}: {e}", exc_info=True)
        return UboResult(company_name=company_name, error=f"An unexpected error occurred: {e}")

async def analyze_entity_risk(
    company_name: str,
    jurisdiction: str,
    risk_weights: Dict[str, int] = MLINT_RISK_WEIGHTS,
) -> EntityRiskResult:
    """
    Analyzes an entity for shell company indicators and risk.
    [MLINT 2.0] Now calls get_ubo_data, which also updates the graph.
    """
    if not API_KEYS.aml_api_key:
        return EntityRiskResult(
            company_name=company_name, jurisdiction=jurisdiction,
            error="AML API key (aml_api_key) not found in .env file."
        )
    if not MLINT_AML_API_URL:
        return EntityRiskResult(
            company_name=company_name, jurisdiction=jurisdiction,
            error="MLINT_AML_API_URL not found in config."
        )

    logger.info(f"Analyzing entity risk for: {company_name} in {jurisdiction}")
    params = {"companyName": company_name, "jurisdiction": jurisdiction}
    headers = {"Authorization": f"Bearer {API_KEYS.aml_api_key}"}

    risk_factors: List[str] = []
    shell_indicators: List[str] = []
    risk_score = 0
    pep_links = 0
    adverse_media_hits = 0
    sanctions_hits = 0

    # 1. Check Jurisdiction Risk
    jurisdiction_data = get_jurisdiction_risk(jurisdiction)
    if jurisdiction_data.is_fatf_black_list:
        risk_score += risk_weights.get("fatf_black_list", 50)
        risk_factors.append(f"Registered in FATF Black List jurisdiction: {jurisdiction}")
    elif jurisdiction_data.is_fatf_grey_list:
        risk_score += risk_weights.get("fatf_grey_list", 25)
        risk_factors.append(f"Registered in FATF Grey List jurisdiction: {jurisdiction}")

    # 2. [ENHANCEMENT] Fetch UBO Data (this now also updates Neo4j)
    ubo_result = await get_ubo_data(company_name)
    if not ubo_result.error:
        for owner in ubo_result.ultimate_beneficial_owners:
            if owner.is_pep:
                pep_links += 1
                risk_factors.append(f"UBO link to PEP: {owner.name} ({owner.ownership_percentage}%)")
    
    # 3. Real Async API Call (Sanctions/PEP/Adverse Media)
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(MLINT_AML_API_URL, params=params, headers=headers, timeout=30.0)
            response.raise_for_status() 
            data = response.json()
            
            pep_links += data.get("pep_links", 0) 
            if pep_links > 0:
                risk_score += pep_links * risk_weights.get("pep_link", 30)
                risk_factors.append(f"Found {pep_links} total Politically Exposed Persons (PEPs).")

            sanctions_hits = data.get("sanctions_hits", 0)
            if sanctions_hits > 0:
                risk_score += sanctions_hits * risk_weights.get("sanctions_hit", 70)
                risk_factors.append(f"[bold red]Direct hit on {sanctions_hits} sanctions lists (e.g., OFAC).[/bold red]")
            
            adverse_media_hits = data.get("adverse_media_hits", 0)
            if adverse_media_hits > 20: 
                risk_score += risk_weights.get("adverse_media_high", 15)
                risk_factors.append(f"High adverse media: {adverse_media_hits} hits.")

            for indicator in data.get("shell_indicators", []):
                shell_indicators.append(indicator)
                risk_score += risk_weights.get("shell_indicator", 10)

    except httpx.RequestError as e:
        logger.error(f"HTTP request failed for entity {company_name}: {e}", exc_info=True)
        return EntityRiskResult(company_name=company_name, jurisdiction=jurisdiction, error=f"API request error: {e}")
    except Exception as e:
        logger.error(f"Failed to screen entity {company_name}: {e}", exc_info=True)
        return EntityRiskResult(company_name=company_name, jurisdiction=jurisdiction, error=f"An unexpected error occurred: {e}")

    return EntityRiskResult(
        company_name=company_name, jurisdiction=jurisdiction,
        risk_score=min(risk_score, 100), risk_factors=risk_factors,
        pep_links=pep_links, adverse_media_hits=adverse_media_hits,
        shell_company_indicators=shell_indicators, sanctions_hits=sanctions_hits,
    )


async def check_crypto_wallet(wallet_address: str) -> CryptoWalletScreenResult:
    """
    Screens a crypto wallet against a real analytics API.
    """
    api_key = API_KEYS.chainalysis_api_key or API_KEYS.trm_labs_api_key or API_KEYS.chain_api_key
    if not api_key:
        return CryptoWalletScreenResult(
            wallet_address=wallet_address,
            error="No Crypto analytics API key found (e.g., CHAINALYSIS_API_KEY).",
        )
    if not MLINT_CHAIN_API_URL:
        return CryptoWalletScreenResult(
            wallet_address=wallet_address,
            error="MLINT_CHAIN_API_URL not found in config.",
        )

    logger.info(f"Screening wallet: {wallet_address} (using real API)")
    params = {"address": wallet_address}
    headers = {"Authorization": f"Bearer {api_key}"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(MLINT_CHAIN_API_URL, params=params, headers=headers, timeout=30.0)
            response.raise_for_status()
            data = response.json()
        
        risk_level = "Low"; risk_score = data.get('risk_score', 0)
        if risk_score > 75: risk_level = "High"
        elif risk_score > 40: risk_level = "Medium"

        return CryptoWalletScreenResult(
            wallet_address=wallet_address, risk_level=risk_level,
            risk_score=risk_score, known_associations=data.get("associations", []),
            mixer_interaction=data.get("mixer_interaction", False),
            sanctioned_entity_link=data.get("sanctioned_entity_link", False)
        )
    except httpx.RequestError as e:
        logger.error(f"HTTP request failed for wallet {wallet_address}: {e}", exc_info=True)
        return CryptoWalletScreenResult(wallet_address=wallet_address, error=f"API request error: {e}")
    except Exception as e:
        logger.error(f"Failed to screen wallet {wallet_address}: {e}", exc_info=True)
        return CryptoWalletScreenResult(wallet_address=wallet_address, error=f"An unexpected error occurred: {e}")

def analyze_transactions(
    transactions: List[Transaction],
    graph_output_file: Optional[str] = None
) -> TransactionAnalysisResult:
    """
    [DEPRECATED for large datasets]
    Analyzes a BATCH of transactions using pandas and networkx.
    """
    logger.warning(
        "Using batch 'analyze_transactions'. This uses Dask for parallel processing"
        " but is NOT recommended for large-scale or real-time analysis."
    )
    if not transactions:
        return TransactionAnalysisResult(total_transactions=0, total_volume=0)
    
    try:
        df = pd.DataFrame([tx.model_dump() for tx in transactions])
        ddf = dd.from_pandas(df, npartitions=4)
        
        df['date'] = pd.to_datetime(df['date'])
        total_transactions = len(df)
        total_volume = ddf['amount'].sum().compute()
        
        structuring_alerts = []
        high_risk_flows = []
        
        logger.critical(
            "SKIPPING 'networkx.simple_cycles' due to extreme scalability issues."
            " Use 'mlint graph find-cycles' command."
        )
        round_tripping_alerts = [] 

        features_used = ['amount']
        df['sender_jurisdiction_risk'] = df['sender_jurisdiction'].apply(lambda x: get_jurisdiction_risk(x).risk_score)
        df['receiver_jurisdiction_risk'] = df['receiver_jurisdiction'].apply(lambda x: get_jurisdiction_risk(x).risk_score)
        df['sender_tx_frequency'] = df.groupby('sender_id')['sender_id'].transform('count')
        features_used.extend(['sender_jurisdiction_risk', 'receiver_jurisdiction_risk', 'sender_tx_frequency'])
        
        scaler = StandardScaler(); features_df = df[features_used]
        features_scaled = scaler.fit_transform(features_df)
        model = IsolationForest(contamination=0.05, random_state=42).fit(features_scaled)
        df['anomaly'] = model.predict(features_scaled)
        df['anomaly'] = df['anomaly'].map({1: 0, -1: 1})
        anomaly_score = df['anomaly'].mean() * 100
        
        logger.info(f"Batch analysis complete. Anomaly score: {anomaly_score:.2f}%")

        if graph_output_file:
            logger.info(f"Generating transaction graph visualization at {graph_output_file}")
            G = nx.from_pandas_edgelist(df, source='sender_id', target='receiver_id', create_using=nx.DiGraph)
            net = Network(height="750px", width="100%", directed=True, notebook=False)
            net.from_nx(G); net.set_options("""var options = { "physics": { "solver": "forceAtlas2Based" } }""")
            net.save_graph(graph_output_file)

        return TransactionAnalysisResult(
            total_transactions=total_transactions, total_volume=total_volume,
            structuring_alerts=structuring_alerts, round_tripping_alerts=round_tripping_alerts,
            high_risk_jurisdiction_flows=high_risk_flows, anomaly_score=anomaly_score,
            anomaly_features_used=features_used
        )
    except Exception as e:
        logger.error(f"Failed during batch transaction analysis: {e}", exc_info=True)
        return TransactionAnalysisResult(error=str(e), total_transactions=0, total_volume=0)


def export_entity_to_stix(result: EntityRiskResult) -> str:
    """
    Generates a STIX 2.1 bundle for a high-risk entity.
    """
    logger.info(f"Generating STIX 2.1 report for {result.company_name}")
    company_identity = Identity(name=result.company_name, identity_class="organization")
    indicator_description = f"High ML risk: {result.company_name}. Score: {result.risk_score}/100. Factors: {'; '.join(result.risk_factors)}"
    pattern = f"[identity:name = '{result.company_name}']"
    indicator = Indicator(name=f"High Risk Entity: {result.company_name}", description=indicator_description, pattern_type="stix", pattern=pattern, indicator_types=["malicious-activity"], confidence=(result.risk_score))
    relationship = Relationship(relationship_type="indicates", source_ref=indicator.id, target_ref=company_identity.id)
    bundle = Bundle(objects=[company_identity, indicator, relationship])
    return bundle.serialize(pretty=True)

# --- [MLINT 2.0] New Functions ---

def detect_layering(driver: Driver, start_node_id: str, start_node_type: str = "Wallet", max_depth: int = 5, time_window_days: int = 7) -> Optional[AMLAlert]:
    """
    Detects potential layering patterns in the graph starting from a given node.

    Looks for:
    1. 'Smurfing' (many small inputs) followed by consolidation.
    2. 'Peel chains' or complex dispersal patterns.
    3. Rapid movement of funds through multiple unrelated entities.
    """
    logger.info(f"Running layering detection for {start_node_type} {start_node_id}")
    
    # This query uses APOC path expansion to find transaction chains.
    # It scores paths based on length, duration, and high-risk intermediate nodes.
    # NOTE: This query assumes relationships are :SENT_TRANSACTION or :RECEIVED_TRANSACTION
    # and that they have a 'timestamp' property (as milliseconds).
    # Adjust labels and properties as needed for your graph schema.
    
    query = f"""
    MATCH (start:{start_node_type} {{id: $start_node_id}})
    // Find paths of transactions within the time window
    CALL apoc.path.expandConfig(start, {{
        relationships: "SENT_TO>|<SENT_TO", // Using SENT_TO in either direction
        minLevel: 2,
        maxLevel: $max_depth,
        uniqueness: "NODE_GLOBAL"
    }}) YIELD path
    
    // Filter nodes in the path to ensure they are financial entities
    WHERE all(node in nodes(path) WHERE node:Wallet OR node:Company OR node:Person OR node:Account)
    
    // Get all transactions in the path
    WITH path, [rel in relationships(path) | rel.date] AS timestamps
    
    // Convert string timestamps to datetime objects for comparison
    WITH path, 
         [ts IN timestamps WHERE ts IS NOT NULL] AS valid_timestamps
    WHERE size(valid_timestamps) > 0
    WITH path, 
         [dt in valid_timestamps | apoc.temporal.fromIso8601(dt)] AS datetimes
    WITH path, 
         duration.between(apoc.coll.min(datetimes), apoc.coll.max(datetimes)).milliseconds AS duration_ms
    
    // Check if duration is within the time window (duration_ms is in milliseconds)
    WHERE duration_ms < ($time_window_days * 24 * 60 * 60 * 1000)
    
    WITH path, duration_ms, length(path) AS path_length, nodes(path) AS entities
    
    // Exclude simple A -> B -> A bounces
    WHERE entities[0] <> entities[-1]
    
    // Check for high-risk flags in intermediate nodes
    WITH path, duration_ms, path_length, entities,
         size([node in entities[1..-1] | 
               (node:Wallet AND node.mixer_interaction = true) OR 
               (node:Account AND node.jurisdiction IN $fatf_black_list) OR
               (node:Person AND (node.is_pep = true OR node.is_sanctioned = true))
         ]) AS high_risk_hops
    
    // Scoring logic: longer paths, more high-risk hops, faster movement = higher risk
    WHERE path_length > 2 OR high_risk_hops > 0
    RETURN 
        path, 
        duration_ms, 
        path_length, 
        high_risk_hops,
        [n in entities | labels(n) + {{id: n.id, name: n.name}}] AS entity_trail
    ORDER BY path_length DESC, high_risk_hops DESC, duration_ms ASC
    LIMIT 1
    """
    
    params = {
        "start_node_id": start_node_id,
        "max_depth": max_depth,
        "time_window_days": time_window_days,
        "fatf_black_list": list(FATF_BLACK_LIST) # Pass risk lists as params
    }

    try:
        with driver.session() as session:
            result = session.run(query, params).single()
            
            if result:
                # Calculate confidence score (heuristic)
                confidence = min(1.0, 0.5 + (result['path_length'] * 0.1) + (result['high_risk_hops'] * 0.2))
                message = f"Potential layering detected: {result['path_length']}-hop transaction chain involving {result['high_risk_hops']} high-risk entities completed in {result['duration_ms'] / 1000.0 :.2f}s."
                
                return AMLAlert(
                    type="LAYERING",
                    entity_id=start_node_id,
                    confidence=confidence,
                    message=message,
                    evidence={
                        "path_length": result['path_length'],
                        "high_risk_hops": result['high_risk_hops'],
                        "duration_ms": result['duration_ms'],
                        "entity_trail": result['entity_trail']
                    }
                )
    except Exception as e:
        # Handle common errors like APOC or temporal function not found
        if "Unknown function" in str(e):
            logger.error(f"Error during layering detection: {e}. Ensure APOC and temporal functions are installed in Neo4j.")
        else:
            logger.error(f"Error during layering detection query for {start_node_id}: {e}", exc_info=True)
    
    return None


def detect_straw_company(driver: Driver, company_id: str, company_name: Optional[str] = None) -> Optional[AMLAlert]:
    """
    Analyzes a company entity for signs of being a 'straw' or 'shell' company.
    Can search by company_id or company_name.

    Red flags:
    1. Recently registered.
    2. Linked to high-risk jurisdictions.
    3. UBOs (Ultimate Beneficial Owners) are PEPs or sanctioned.
    4. Address is a known mail drop or virtual office.
    """
    if not company_id and not company_name:
        raise ValueError("Must provide either company_id or company_name")

    logger.info(f"Running straw company detection for {company_id or company_name}")

    # Use a MATCH clause that can handle either ID or name
    match_clause = f"MATCH (c:Company {{id: $company_id}})"
    params = {"company_id": company_id}
    
    if not company_id:
        match_clause = f"MATCH (c:Company {{name: $company_name}})"
        params = {"company_name": company_name}

    query = f"""
    {match_clause}
    OPTIONAL MATCH (c)-[:HAS_UBO]->(ubo:Person)
    // Assuming jurisdiction is a property on the Company node for simplicity
    // If it's a separate node: OPTIONAL MATCH (c)-[:REGISTERED_IN]->(j:Jurisdiction)
    RETURN 
        c.id AS id,
        c.name AS name,
        c.registration_date AS reg_date, // Assumes ISO 8601 string
        c.address AS address,
        c.jurisdiction AS jurisdiction_name, // Property on Company node
        collect(DISTINCT {{
            id: ubo.id, 
            name: ubo.name,
            is_pep: ubo.is_pep, 
            is_sanctioned: ubo.is_sanctioned
        }}) AS ubos
    """
    
    try:
        with driver.session() as session:
            record = session.run(query, params).single()
    
        if not record or not record.get("id"):
            logger.warning(f"No company found for {company_id or company_name} for straw detection.")
            return None

        risk_score = 0.0
        evidence = {}
        entity_id = record.get('id')
        entity_name = record.get('name')

        # 1. Recently registered
        reg_date_str = record.get("reg_date")
        if reg_date_str:
            try:
                # Assuming reg_date_str is like '2023-10-27'
                reg_date = datetime.fromisoformat(reg_date_str.split('T')[0])
                if (datetime.utcnow() - reg_date) < timedelta(days=365):
                    risk_score += 0.3
                    evidence["registration"] = f"Recently registered on {reg_date_str}"
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid reg_date format for {entity_id}: {reg_date_str} - {e}")

        # 2. High-risk jurisdiction
        jurisdiction_name = record.get("jurisdiction_name")
        if jurisdiction_name:
            jurisdiction_risk = get_jurisdiction_risk(jurisdiction_name)
            if jurisdiction_risk.risk_score > 70: # High risk (Black List)
                risk_score += 0.4
                evidence["jurisdiction"] = f"High-risk jurisdiction: {jurisdiction_name} ({jurisdiction_risk.details})"
            elif jurisdiction_risk.risk_score > 50: # Medium risk (Grey List)
                risk_score += 0.2
                evidence["jurisdiction"] = f"Medium-risk jurisdiction: {jurisdiction_name} ({jurisdiction_risk.details})"

        # 3. High-risk UBOs
        high_risk_ubos = []
        for ubo in record.get("ubos", []):
            if ubo.get("id") and (ubo.get("is_pep") or ubo.get("is_sanctioned")):
                risk_score += 0.5 # High penalty
                ubo_status = "PEP" if ubo.get("is_pep") else "Sanctioned"
                high_risk_ubos.append(f"{ubo.get('name', ubo.get('id'))} ({ubo_status})")
        
        if high_risk_ubos:
            evidence["high_risk_ubos"] = high_risk_ubos

        # 4. Address check (mocking a known list of shell addresses)
        KNOWN_SHELL_ADDRESSES = ["123 PO Box", "Regus", "Virtual Office", "Mail Drop", "c/o"]
        address = record.get("address", "")
        if address and any(shell_addr.lower() in address.lower() for shell_addr in KNOWN_SHELL_ADDRESSES):
            risk_score += 0.3
            evidence["address"] = f"Address matches known virtual/mail drop pattern: {address}"

        confidence = min(1.0, risk_score)
        ALERT_THRESHOLD = 0.6

        if confidence > ALERT_THRESHOLD:
            message = f"Company {entity_name} ({entity_id}) flagged as potential straw/shell company with confidence {confidence:.2f}."
            return AMLAlert(
                type="STRAW_COMPANY",
                entity_id=entity_id,
                confidence=confidence,
                message=message,
                evidence=evidence
            )
            
    except Exception as e:
        logger.error(f"Error during straw company detection for {company_id or company_name}: {e}", exc_info=True)
    
    return None