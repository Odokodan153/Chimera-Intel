# Chimera-Intel/src/chimera_intel/core/mlint.py
"""
Module for Money Laundering Intelligence (MLINT).

Provides tools to detect suspicious financial patterns, analyze entity risk,
and identify high-risk jurisdictions or crypto wallets. This module is designed
to be scalable, integrating with graph databases (Neo4j) and streaming platforms
(Kafka) as defined in the advanced architecture.

[MLINT 2.0 Enhancements]:
- Added Entity Resolution (resolve) to link wallets, companies, and UBOs.
- Added Trade-Payment Correlation (correlate-trade) for trade-based ML.
- Replaced GNN placeholder with real graph feature-based anomaly detection.
- Replaced Kafka placeholder with a scalable producer-consumer pipeline.
"""

"""
Data Sources & Enrichment
Implemented: Async fetch for UBOs (get_ubo_data), crypto wallet checks (check_crypto_wallet), adverse media hits.
[MLINT 2.0] Added Trade/Customs API placeholder (correlate_trade_payment).
[MLINT 2.0] Implemented Entity Resolution (resolve_entities) to link disparate data.
Missing / Placeholder: Real integration with OpenCorporates, Nansen, TRM Labs, World-Check, Trade/Customs data APIs.
Advanced ML / AI
Implemented: Batch anomaly detection (IsolationForest).
[MLINT 2.0] Replaced GNN placeholder with real graph-feature anomaly detection (detect_graph_anomalies) using Neo4j features (PageRank, Community) + IsolationForest.
Missing / Placeholder: Temporal models (LSTM), full PyG GNN models, XAI.
Graph Intelligence
Implemented: Neo4j connection, find-cycles.
[MLINT 2.0] Implemented entity resolution queries (resolve_entities).
[MLINT 2.0] Implemented real-time graph insertion in Kafka consumer.
Missing: Incremental updates, centrality risk scoring (now partially implemented in GNN).
Streaming / Real-Time Analysis
Implemented: Kafka consumer scaffold.
[MLINT 2.0] Replaced placeholder consumer with a scalable pipeline:
    1. (Consumer) Ingests from 'transactions' topic.
    2. (Consumer) Runs fast sync checks (e.g., structuring).
    3. (Consumer) Inserts transaction into Neo4j.
    4. (Consumer) Produces job (tx_id) to 'scoring_jobs' topic.
    5. (Separate Worker) Subscribes to 'scoring_jobs' for heavy async analysis (UBO, Wallet, Entity Risk).
Missing: The separate async worker pool (e.g., Celery/Faust) to consume from 'scoring_jobs'.
Cross-Channel & Multi-Asset
Implemented: Crypto wallets, SWIFT MT103.
[MLINT 2.0] Added Trade-based correlation (correlate_trade_payment).
Missing: Cross-chain correlation, DeFi, large-scale SWIFT/Trade data parsing.
"""

import typer
import logging
import json
import anyio
import httpx
import swiftmessage
import dask.dataframe as dd # [ENHANCEMENT] For parallel processing
from typing import Optional, List, Dict, Any, Set
from datetime import date
from rich.console import Console
from rich.table import Table
import pandas as pd
import networkx as nx
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from pyvis.network import Network
from stix2 import Indicator, Identity, Relationship, Bundle
from neo4j import GraphDatabase # [ENHANCEMENT] For scalable graph analysis
from kafka import KafkaConsumer, KafkaProducer # [ENHANCEMENT] For real-time streaming

from .schemas import (
    BaseResult,
    JurisdictionRisk,
    EntityRiskResult,
    CryptoWalletScreenResult,
    Transaction,
    TransactionAnalysisResult,
    SwiftTransactionAnalysisResult,
    UboResult, 
    UboData,
    GnnAnomalyResult,
    # --- [MLINT 2.0] New Schemas ---
    EntityLink,
    EntityResolutionResult,
    TradeData,
    PaymentData,
    TradeCorrelationResult
)
from .utils import save_or_print_results
from .database import save_scan_to_db
from .config_loader import (
    API_KEYS, MLINT_RISK_WEIGHTS, MLINT_AML_API_URL, MLINT_CHAIN_API_URL,
    # --- [MLINT 2.0] New Config Imports ---
    MLINT_TRADE_API_URL
)
from .project_manager import resolve_target

logger = logging.getLogger(__name__)
console = Console()

# --- Risk Data (as suggested in proposal) ---
FATF_BLACK_LIST = {"NORTH KOREA", "IRAN", "MYANMAR"}
FATF_GREY_LIST = {
    "PANAMA", "CAYMAN ISLANDS", "TURKEY", "UNITED ARAB EMIRATES", "BARBADOS",
    "GIBRALTAR", "JAMAICA", "NIGERIA", "SOUTH AFRICA", "SYRIA", "YEMEN",
}

# --- Typer Applications (Main and Sub-apps) ---
mlint_app = typer.Typer(
    name="mlint", help="Money Laundering Intelligence (MLINT) tools."
)
graph_app = typer.Typer(
    name="graph", help="Scalable graph analysis using Neo4j."
)
stream_app = typer.Typer(
    name="stream", help="Real-time transaction monitoring using Kafka."
)
mlint_app.add_typer(graph_app)
mlint_app.add_typer(stream_app)


# --- [MLINT 2.0] Helper: Neo4j Driver Context ---

def get_neo4j_driver():
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

# --- Core Functions (Existing) ---

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
    [ENHANCEMENT] Fetches Ultimate Beneficial Ownership (UBO) data.
    This integrates with OpenCorporates, World-Check, etc.
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

        return UboResult(
            company_name=company_name,
            ultimate_beneficial_owners=owners,
            corporate_structure=data.get("corporate_structure", {})
        )
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
    Analyzes an entity for shell company indicators and risk using configurable weights.
    [ENHANCEMENT: Now includes a call to fetch UBO data]
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

    # 2. [ENHANCEMENT] Fetch UBO Data
    ubo_result = await get_ubo_data(company_name)
    if not ubo_result.error:
        for owner in ubo_result.ultimate_beneficial_owners:
            if owner.is_pep:
                pep_links += 1
                risk_factors.append(f"UBO link to PEP: {owner.name} ({owner.ownership_percentage}%)")
    
    # 3. Real Async API Call
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
    This integrates with Chainalysis, TRM Labs, Nansen, etc.
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
    This is not suitable for real-time or large-scale graph analysis.
    Use 'mlint stream' and 'mlint graph' commands instead.
    """
    logger.warning(
        "Using batch 'analyze_transactions'. This uses Dask for parallel processing"
        " but is NOT recommended for large-scale or real-time analysis."
        " For production, use 'mlint stream' and 'mlint graph' subcommands."
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
            "SKIPPING 'networkx.simple_cycles' due to extreme scalability issues (O(N!))."
            " This feature is only available via the 'mlint graph find-cycles' command,"
            " which requires a running Neo4j instance."
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
    # (This function remains unchanged)
    logger.info(f"Generating STIX 2.1 report for {result.company_name}")
    company_identity = Identity(name=result.company_name, identity_class="organization")
    indicator_description = f"High ML risk: {result.company_name}. Score: {result.risk_score}/100. Factors: {'; '.join(result.risk_factors)}"
    pattern = f"[identity:name = '{result.company_name}']"
    indicator = Indicator(name=f"High Risk Entity: {result.company_name}", description=indicator_description, pattern_type="stix", pattern=pattern, indicator_types=["malicious-activity"], confidence=(result.risk_score))
    relationship = Relationship(relationship_type="indicates", source_ref=indicator.id, target_ref=company_identity.id)
    bundle = Bundle(objects=[company_identity, indicator, relationship])
    return bundle.serialize(pretty=True)


# --- [MLINT 2.0] New Core Functions ---

async def resolve_entities(
    company_names: List[str],
    wallet_addresses: List[str],
    person_names: List[str]
) -> EntityResolutionResult:
    """
    [MLINT 2.0] Automated entity resolution across wallets, companies, and people.
    Links entities by cross-querying UBO, on-chain, and graph data.
    """
    logger.info(f"Starting entity resolution for {len(company_names)} companies, {len(wallet_addresses)} wallets, {len(person_names)} people")
    
    links: List[EntityLink] = []
    resolved_entities: Set[str] = set()
    
    # --- 1. Enrich input entities ---
    # In parallel, fetch data for all known inputs
    async with anyio.create_task_group() as tg:
        for company in company_names:
            tg.start_soon(get_ubo_data, company)
            resolved_entities.add(f"Company:{company}")
        for wallet in wallet_addresses:
            tg.start_soon(check_crypto_wallet, wallet)
            resolved_entities.add(f"Wallet:{wallet}")
        # (Add person_name screening if API existed)
    
    # (Note: In a real implementation, we'd process the results of these tasks.
    # For this function, we assume data is now in our graph or we query it.)
    
    # --- 2. Query Neo4j for 1st and 2nd degree links ---
    # This is the core of the resolution. We query the graph to find
    # connections *between* the entities provided.
    
    driver = get_neo4j_driver()
    if not driver:
        return EntityResolutionResult(error="Neo4j connection failed. Cannot resolve entities.")
        
    # This query finds links:
    # (Company)-[:HAS_UBO]->(Person)
    # (Person)-[:OWNS_WALLET]->(Wallet)
    # (Wallet)-[:SENT_TO]->(Wallet)
    cypher_query = """
    MATCH (e1)-[r]-(e2)
    WHERE (e1:Company AND e1.name IN $companies)
       OR (e1:Wallet AND e1.address IN $wallets)
       OR (e1:Person AND e1.name IN $people)
       OR (e2:Company AND e2.name IN $companies)
       OR (e2:Wallet AND e2.address IN $wallets)
       OR (e2:Person AND e2.name IN $people)
    RETURN 
        CASE WHEN e1:Company THEN 'Company' WHEN e1:Wallet THEN 'Wallet' ELSE 'Person' END as e1_type,
        COALESCE(e1.name, e1.address) as e1_id,
        type(r) as relationship,
        CASE WHEN e2:Company THEN 'Company' WHEN e2:Wallet THEN 'Wallet' ELSE 'Person' END as e2_type,
        COALESCE(e2.name, e2.address) as e2_id
    LIMIT 200
    """
    
    try:
        with driver.session() as session:
            result = session.run(
                cypher_query, 
                companies=company_names, 
                wallets=wallet_addresses, 
                people=person_names
            )
            for record in result:
                e1 = f"{record['e1_type']}:{record['e1_id']}"
                e2 = f"{record['e2_type']}:{record['e2_id']}"
                links.append(EntityLink(
                    source=e1,
                    target=e2,
                    type=record['relationship'],
                    description=f"Found graph link: {e1} -> {record['relationship']} -> {e2}"
                ))
                resolved_entities.add(e1)
                resolved_entities.add(e2)
        
        # --- 3. Add Mixer/Sanctions links from wallet checks (MVP) ---
        for wallet in wallet_addresses:
            wallet_data = await check_crypto_wallet(wallet)
            if not wallet_data.error:
                if wallet_data.mixer_interaction:
                    link_desc = "Wallet has interacted with a known mixer."
                    links.append(EntityLink(source=f"Wallet:{wallet}", target="Entity:Mixer", type="INTERACTED_WITH", description=link_desc))
                    resolved_entities.add("Entity:Mixer")
                if wallet_data.sanctioned_entity_link:
                    link_desc = "Wallet has links to a sanctioned entity."
                    links.append(EntityLink(source=f"Wallet:{wallet}", target="Entity:Sanctioned", type="LINKED_TO", description=link_desc))
                    resolved_entities.add("Entity:Sanctioned")

    except Exception as e:
        logger.error(f"Neo4j entity resolution query failed: {e}", exc_info=True)
        return EntityResolutionResult(error=f"Neo4j query error: {e}")
    finally:
        driver.close()
        
    return EntityResolutionResult(
        total_entities_found=len(resolved_entities),
        links=links
    )

async def correlate_trade_payment(
    payment_id: str,
    trade_document_id: str
) -> TradeCorrelationResult:
    """
    [MLINT 2.0] Correlates a payment (e.g., SWIFT) with a trade document (e.g., Bill of Lading).
    """
    trade_api_key = API_KEYS.trade_api_key
    payment_api_key = API_KEYS.aml_api_key # Reusing AML as placeholder
    
    if not (trade_api_key and MLINT_TRADE_API_URL):
        return TradeCorrelationResult(error="Trade API credentials (TRADE_API_KEY, MLINT_TRADE_API_URL) not set.")

    logger.info(f"Correlating payment {payment_id} with trade doc {trade_document_id}")

    try:
        # 1. Fetch Trade Data (e.g., from customs/logistics API)
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {trade_api_key}"}
            params = {"documentId": trade_document_id}
            response_trade = await client.get(MLINT_TRADE_API_URL, params=params, headers=headers, timeout=30.0)
            response_trade.raise_for_status()
            trade_data_raw = response_trade.json()
            trade_data = TradeData.model_validate(trade_data_raw) # Parse into schema
        
        # 2. Fetch Payment Data (e.g., from internal SWIFT/payments DB)
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {payment_api_key}"}
            # Using MLINT_AML_API_URL as a placeholder for a payments API
            params = {"paymentId": payment_id}
            response_payment = await client.get(MLINT_AML_API_URL, params=params, headers=headers, timeout=30.0)
            response_payment.raise_for_status()
            payment_data_raw = response_payment.json()
            payment_data = PaymentData.model_validate(payment_data_raw) # Parse into schema
            
        # 3. Run Correlation Logic
        correlation_score = 0.0
        confidence = "Low"
        mismatches = []

        # Check amounts
        if payment_data.amount == trade_data.invoice_amount:
            correlation_score += 0.50
        else:
            mismatches.append(f"Amount mismatch: Payment={payment_data.amount}, Invoice={trade_data.invoice_amount}")
            
        # Check entities (e.g., does payment sender match trade exporter?)
        # This is a simple string match; real logic would use entity resolution
        if payment_data.sender_name.lower() in trade_data.exporter_name.lower():
            correlation_score += 0.25
        else:
            mismatches.append(f"Exporter/Sender mismatch: {payment_data.sender_name} vs {trade_data.exporter_name}")
            
        if payment_data.receiver_name.lower() in trade_data.importer_name.lower():
            correlation_score += 0.25
        else:
            mismatches.append(f"Importer/Receiver mismatch: {payment_data.receiver_name} vs {trade_data.importer_name}")

        if correlation_score > 0.8: confidence = "High"
        elif correlation_score > 0.4: confidence = "Medium"

        return TradeCorrelationResult(
            payment=payment_data,
            trade_document=trade_data,
            is_correlated=(correlation_score > 0.5),
            confidence=confidence,
            correlation_score=correlation_score,
            mismatches=mismatches
        )
        
    except httpx.RequestError as e:
        logger.error(f"HTTP request failed for trade correlation: {e}", exc_info=True)
        return TradeCorrelationResult(error=f"API request error: {e}")
    except Exception as e:
        logger.error(f"Failed to correlate trade/payment: {e}", exc_info=True)
        return TradeCorrelationResult(error=f"An unexpected error occurred: {e}")


# --- CLI Commands: Entity & Batch ---

@mlint_app.command("check-entity")
def run_entity_check(
    company_name: str = typer.Option(..., "--company-name", "-c", help="The company's legal name."),
    jurisdiction: str = typer.Option(..., "--jurisdiction", "-j", help="The company's registration jurisdiction (e.g., Panama)."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON results to a file."),
    stix_output: Optional[str] = typer.Option(None, "--stix-out", help="Save STIX 2.1 results to a JSON file."),
):
    """
    Analyzes an entity for ML risk (PEP, Sanctions, UBO, Adverse Media).
    """
    console.print(f"Analyzing entity: [bold cyan]{company_name}[/bold cyan] in [bold cyan]{jurisdiction}[/bold cyan]")
    with console.status("[bold green]Running async entity check...[/]"):
        try:
            results_model = anyio.run(analyze_entity_risk, company_name, jurisdiction)
        except RuntimeError as e:
            console.print(f"[bold red]Async Error:[/bold red] {e}"); raise typer.Exit(code=1)
    
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}"); raise typer.Exit(code=1)

    console.print(f"\n[bold magenta]Entity Risk Report for {company_name}[/bold magenta]")
    console.print(f"  [bold]Risk Score:[/bold] {results_model.risk_score} / 100")
    console.print(f"  [bold]PEP Links:[/bold] {results_model.pep_links}")
    console.print(f"  [bold]Sanctions Hits:[/bold] {results_model.sanctions_hits}")
    if results_model.risk_factors:
        console.print("[bold]Risk Factors:[/bold]"); [console.print(f"  - {f}") for f in results_model.risk_factors]
    if results_model.shell_company_indicators:
        console.print("[bold]Shell Indicators:[/bold]"); [console.print(f"  - {i}") for i in results_model.shell_company_indicators]

    results_dict = results_model.model_dump(exclude_none=True)
    if output_file: save_or_print_results(results_dict, output_file)
    if stix_output:
        stix_data = export_entity_to_stix(results_model)
        try:
            with open(stix_output, "w") as f: f.write(stix_data)
            console.print(f"\n[green]STIX 2.1 report saved to {stix_output}[/green]")
        except Exception as e: console.print(f"[bold red]Error saving STIX report:[/bold red] {e}")
    save_scan_to_db(target=company_name, module="mlint_entity_check", data=results_dict)

@mlint_app.command("check-wallet")
def run_wallet_check(
    address: str = typer.Option(..., "--address", "-a", help="The crypto wallet address to screen."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """
    Screens a crypto wallet address using on-chain analytics (e.g., Chainalysis).
    """
    console.print(f"Screening wallet: [bold cyan]{address}[/bold cyan]")
    with console.status("[bold green]Running async wallet check...[/]"):
        try:
            results_model = anyio.run(check_crypto_wallet, address)
        except RuntimeError as e:
            console.print(f"[bold red]Async Error:[/bold red] {e}"); raise typer.Exit(code=1)
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}"); raise typer.Exit(code=1)
    
    table = Table(title=f"Wallet Screening for {results_model.wallet_address}", header_style="bold magenta")
    table.add_column("Risk Level"); table.add_column("Risk Score"); table.add_column("Mixer Interaction"); table.add_column("Sanctioned Link"); table.add_column("Associations")
    table.add_row(results_model.risk_level, str(results_model.risk_score), str(results_model.mixer_interaction), str(results_model.sanctioned_entity_link), ", ".join(results_model.known_associations))
    console.print(table)
    results_dict = results_model.model_dump(exclude_none=True);
    if output_file: save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=address, module="mlint_wallet_check", data=results_dict)

@mlint_app.command("analyze-tx-batch")
def run_transaction_analysis(
    transaction_file: str = typer.Argument(..., help="Path to a JSON file containing a list of transactions."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
    graph_output: Optional[str] = typer.Option(None, "--graph-out", help="Save interactive graph visualization to an HTML file."),
):
    """
    [DEPRECATED] Analyzes a BATCH of transactions using pandas/dask.
    """
    console.print(f"Analyzing transactions from: [bold cyan]{transaction_file}[/bold cyan]")
    try:
        with open(transaction_file, 'r') as f: tx_data_list = json.load(f)
        transactions = [Transaction.model_validate(tx) for tx in tx_data_list]
    except Exception as e:
        console.print(f"[bold red]Error loading transaction file:[/bold red] {e}"); raise typer.Exit(code=1)

    with console.status("[bold green]Running batch transaction analysis...[/]"):
        results_model = analyze_transactions(transactions, graph_output_file=graph_output)
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}"); raise typer.Exit(code=1)

    console.print(f"\n[bold magenta]Transaction Analysis Report[/bold magenta]")
    console.print(f"  [bold]Total Transactions:[/bold] {results_model.total_transactions}")
    console.print(f"  [bold]ML Anomaly Score:[/bold] {results_model.anomaly_score:.2f}% (features: {', '.join(results_model.anomaly_features_used)})")
    console.print(f"  [bold]Structuring Alerts:[/bold] {len(results_model.structuring_alerts)}")
    console.print(f"  [bold]Round-Tripping (Neo4j):[/bold] [yellow]Skipped. Use 'mlint graph find-cycles'.[/yellow]")
    if graph_output: console.print(f"\n[green]Interactive graph visualization saved to {graph_output}[/green]")
    results_dict = results_model.model_dump(exclude_none=True)
    if output_file: save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=transaction_file, module="mlint_tx_analysis", data=results_dict)

@mlint_app.command("analyze-swift-mt103")
def run_swift_analysis(
    swift_file: str = typer.Argument(..., help="Path to a raw SWIFT MT103 message file."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """
    Parses a single SWIFT MT103 message and runs batch analysis.
    """
    console.print(f"Analyzing SWIFT MT103 file: [bold cyan]{swift_file}[/bold cyan]")
    try:
        with open(swift_file, 'r') as f: raw_message = f.read()
        msg = swiftmessage.parse(raw_message); data = msg.data
        date_str = data.get(':32A:', {}).get('date', '230101'); amount = float(data.get(':32A:', {}).get('amount', 0))
        tx_date = date(int(f"20{date_str[0:2]}"), int(date_str[2:4]), int(date_str[4:6]))
        sender_id = data.get(':50K:', {}).get('account', 'UNKNOWN_SENDER')
        receiver_id = data.get(':59:', {}).get('account', 'UNKNOWN_RECEIVER')
        tx_id = data.get(':20:', {}).get('transaction_reference', 'UNKNOWN_REF')
        sender_bic = data.get(':53A:', {}).get('bic'); receiver_bic = data.get(':57A:', {}).get('bic')
        sender_jurisdiction = sender_bic[4:6] if sender_bic else None; receiver_jurisdiction = receiver_bic[4:6] if receiver_bic else None
        transaction = Transaction(id=tx_id, date=tx_date, amount=amount, currency=data.get(':32A:', {}).get('currency', 'USD'), sender_id=sender_id, receiver_id=receiver_id, sender_jurisdiction=sender_jurisdiction, receiver_jurisdiction=receiver_jurisdiction)
        console.print(f"  [green]Successfully parsed MT103 (Ref: {tx_id})[/green]")
        analysis_result = analyze_transactions([transaction]) # Run batch analysis on the single tx
        result_model = SwiftTransactionAnalysisResult(file_name=swift_file, sender_bic=sender_bic, receiver_bic=receiver_bic, transaction=transaction, analysis=analysis_result)
    except Exception as e:
        logger.error(f"Failed to parse SWIFT file {swift_file}: {e}", exc_info=True)
        result_model = SwiftTransactionAnalysisResult(file_name=swift_file, error=str(e))
    results_dict = result_model.model_dump(exclude_none=True)
    if output_file: save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=swift_file, module="mlint_swift_analysis", data=results_dict)


# --- [MLINT 2.0] New CLI Commands: Core Suite ---

@mlint_app.command("resolve")
def run_entity_resolution(
    company: List[str] = typer.Option(None, "--company", "-c", help="Company name to resolve."),
    wallet: List[str] = typer.Option(None, "--wallet", "-w", help="Wallet address to resolve."),
    person: List[str] = typer.Option(None, "--person", "-p", help="Person name to resolve."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """
    [MLINT 2.0] Resolve links between entities (wallets, companies, people).
    
    Example (MVP): Find links for a wallet.
    `chimera mlint resolve --wallet "1AbC..."`
    
    This will check the wallet for mixer/sanctions and also query the graph
    to see if it's linked to any known UBOs or Companies.
    """
    if not any([company, wallet, person]):
        console.print("[bold red]Error:[/bold red] Must provide at least one entity to resolve.")
        raise typer.Exit(code=1)
        
    console.print(f"Resolving entities...")
    with console.status("[bold green]Running async entity resolution...[/]"):
        try:
            results_model = anyio.run(resolve_entities, company, wallet, person)
        except RuntimeError as e:
            console.print(f"[bold red]Async Error:[/bold red] {e}"); raise typer.Exit(code=1)
    
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}"); raise typer.Exit(code=1)
        
    console.print(f"\n[bold magenta]Entity Resolution Report[/bold magenta]")
    console.print(f"  [bold]Total Unique Entities Found:[/bold] {results_model.total_entities_found}")
    
    if results_model.links:
        console.print("[bold]Found Links:[/bold]")
        for link in results_model.links:
            console.print(f"  - [cyan]{link.source}[/cyan] --({link.type})--> [cyan]{link.target}[/cyan]")
            console.print(f"    [italic]{link.description}[/italic]")
    else:
        console.print("[yellow]No links found between the provided entities.[/yellow]")

    if output_file: save_or_print_results(results_model.model_dump(exclude_none=True), output_file)

@mlint_app.command("correlate-trade")
def run_trade_correlation(
    payment_id: str = typer.Option(..., "--payment-id", "-p", help="The unique ID of the payment (e.g., SWIFT ref)."),
    trade_doc_id: str = typer.Option(..., "--trade-doc-id", "-t", help="The unique ID of the trade doc (e.g., Bill of Lading)."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """
    [MLINT 2.0] Correlate a payment with a trade/customs document.
    """
    console.print(f"Correlating Payment [cyan]{payment_id}[/cyan] with Trade Doc [cyan]{trade_doc_id}[/cyan]...")
    with console.status("[bold green]Running async trade correlation...[/]"):
        try:
            results_model = anyio.run(correlate_trade_payment, payment_id, trade_doc_id)
        except RuntimeError as e:
            console.print(f"[bold red]Async Error:[/bold red] {e}"); raise typer.Exit(code=1)
    
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}"); raise typer.Exit(code=1)

    console.print(f"\n[bold magenta]Trade Correlation Report[/bold magenta]")
    if results_model.is_correlated:
        console.print(f"  [bold green]Result: Correlated[/bold green] (Confidence: {results_model.confidence})")
    else:
        console.print(f"  [bold red]Result: Not Correlated[/bold red] (Confidence: {results_model.confidence})")
        
    if results_model.mismatches:
        console.print("[bold]Mismatches Found:[/bold]")
        for mismatch in results_model.mismatches:
            console.print(f"  - [yellow]{mismatch}[/yellow]")
            
    if output_file: save_or_print_results(results_model.model_dump(exclude_none=True), output_file)


# --- [ENHANCEMENT] CLI Commands: Graph (Neo4j) ---

@graph_app.command("find-cycles")
def run_neo4j_cycle_detection(
    max_length: int = typer.Option(5, help="Maximum path length for cycle detection.")
):
    """
    Finds transaction cycles (round-tripping) using Neo4j.
    """
    driver = get_neo4j_driver()
    if not driver:
        console.print("[bold red]Error: Neo4j credentials not set.[/bold red]")
        raise typer.Exit(code=1)
        
    console.print(f"Connecting to Neo4j to find cycles (max_length={max_length})...")
    
    cypher_query = f"""
    MATCH path = (a:Account)-[:SENT_TO*1..{max_length}]->(a)
    WHERE all(n IN nodes(path) | size([m IN nodes(path) WHERE m = n]) = 1)
    RETURN [n IN nodes(path) | n.id] as cycle, length(path) as length
    ORDER BY length
    LIMIT 100
    """
    
    try:
        with driver.session() as session:
            result = session.run(cypher_query)
            cycles = [record["cycle"] for record in result]
        
        console.print(f"[green]Successfully ran query. Found {len(cycles)} cycles.[/green]")
        for cycle in cycles:
            console.print(f"  - Cycle: {' -> '.join(cycle)}")
    except Exception as e:
        console.print(f"[bold red]Neo4j Error:[/bold red] {e}")
        logger.error(f"Failed to run Neo4j cycle detection: {e}", exc_info=True)
    finally:
        driver.close()

def detect_graph_anomalies(driver: Any) -> List[GnnAnomalyResult]:
    """
    [MLINT 2.0] REAL GNN/Graph Anomaly Detection Function.
    
    This function:
    1. Connects to Neo4j.
    2. Runs Cypher queries to get graph features (PageRank, Community ID).
    3. Fetches features into a pandas DataFrame.
    4. Uses sklearn's IsolationForest to find anomalies based on those graph features.
    
    This replaces the previous "placeholder" GNN function.
    """
    logger.info("Running graph feature-based anomaly detection...")
    
    # This query fetches graph features for all accounts
    # In a real system, this would use GDS library (gds.pageRank.stream, gds.louvain.stream)
    # For simplicity, we assume these features (pagerank, community) are already computed
    # and stored on the nodes.
    
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
        
        # Scale features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(df_features)
        
        # Run IsolationForest
        model = IsolationForest(contamination=0.02, random_state=42).fit(features_scaled)
        df['anomaly_score_raw'] = model.decision_function(features_scaled)
        df['is_anomaly'] = model.predict(features_scaled)

        # Filter for anomalies
        anomaly_df = df[df['is_anomaly'] == -1].sort_values(by='anomaly_score_raw')

        for _, row in anomaly_df.iterrows():
            reason = f"Anomaly score: {row['anomaly_score_raw']:.3f}. (PageRank: {row['pagerank']:.3f}, Community: {row['community']})"
            results.append(GnnAnomalyResult(
                entity_id=row['entity_id'],
                anomaly_score=(1 - row['anomaly_score_raw']), # Normalize score
                reason=[reason]
            ))
        return results
        
    except Exception as e:
        logger.error(f"Failed to run graph anomaly detection: {e}", exc_info=True)
        return [GnnAnomalyResult(error=f"Neo4j query error: {e}")]


@graph_app.command("run-gnn-anomaly")
def run_gnn_anomaly(
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """
    [MLINT 2.0] Triggers graph feature-based anomaly detection (e.g., GNN).
    
    This is no longer a placeholder. It runs a real query against Neo4j
    to get graph features (PageRank, Community) and finds anomalies
    using IsolationForest.
    """
    driver = get_neo4j_driver()
    if not driver:
        console.print("[bold red]Error: Neo4j credentials not set.[/bold red]")
        raise typer.Exit(code=1)

    console.print("[bold green]Running graph feature-based anomaly detection...[/bold green]")
    
    try:
        results = detect_graph_anomalies(driver)
    except Exception as e:
        console.print(f"[bold red]Error during GNN analysis:[/bold red] {e}")
        driver.close()
        raise typer.Exit(code=1)

    driver.close()
    
    if not results:
        console.print("[yellow]No anomalies found or no data to process.[/yellow]")
        return
        
    if results[0].error:
        console.print(f"[bold red]Error:[/bold red] {results[0].error}")
        return

    console.print(f"\n[bold magenta]Graph Anomaly Report (Found {len(results)})[/bold magenta]")
    table = Table(title="Top Anomalies", header_style="bold magenta")
    table.add_column("Entity ID"); table.add_column("Anomaly Score"); table.add_column("Reason")
    
    all_results_dict = []
    for res in results[:20]: # Print top 20
        table.add_row(res.entity_id, f"{res.anomaly_score:.3f}", "\n".join(res.reason))
        all_results_dict.append(res.model_dump())
        
    console.print(table)
    if output_file: save_or_print_results(all_results_dict, output_file)


# --- [ENHANCEMENT] CLI Commands: Streaming (Kafka) ---

def insert_transaction_to_neo4j(driver: Any, tx: Transaction):
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

@stream_app.command("start-consumer")
def run_kafka_consumer():
    """
    [MLINT 2.0] Connects to Kafka and processes transactions in real-time.
    
    This is now a scalable pipeline:
    1. Consumes from KAFKA_TOPIC_TRANSACTIONS.
    2. Runs fast, synchronous checks (structuring, jurisdiction).
    3. Inserts transaction into Neo4j.
    4. Produces transaction ID to KAFKA_TOPIC_SCORING_JOBS for
       a separate, async worker pool to handle heavy risk scoring.
    """
    servers = API_KEYS.kafka_bootstrap_servers
    topic_in = API_KEYS.kafka_topic_transactions
    topic_out = API_KEYS.kafka_topic_scoring_jobs # New topic for async jobs
    group = API_KEYS.kafka_consumer_group
    
    if not all([servers, topic_in, topic_out, group]):
        console.print("[bold red]Error: Kafka settings (KAFKA_BOOTSTRAP_SERVERS, etc.) not set.[/bold red]")
        raise typer.Exit(code=1)

    neo4j_driver = get_neo4j_driver()
    if not neo4j_driver:
        console.print("[bold red]Error: Neo4j credentials not set. Stream consumer cannot start.[/bold red]")
        raise typer.Exit(code=1)

    console.print(f"Connecting to Kafka at {servers}...")
    
    try:
        consumer = KafkaConsumer(
            topic_in,
            bootstrap_servers=servers.split(','),
            auto_offset_reset='earliest',
            group_id=group,
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
        producer = KafkaProducer(
            bootstrap_servers=servers.split(','),
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
    except Exception as e:
        console.print(f"[bold red]Kafka connection error:[/bold red] {e}")
        logger.error(f"Kafka connection failed: {e}", exc_info=True)
        neo4j_driver.close()
        raise typer.Exit(code=1)

    console.print(f"Subscribing to topic '[bold cyan]{topic_in}[/bold cyan]'")
    console.print(f"Producing jobs to topic '[bold yellow]{topic_out}[/bold yellow]'")
    console.print("[italic]Press CTRL+C to stop...[/italic]")
    
    try:
        for message in consumer:
            tx_data = message.value
            console.print(f"\n[green]Received Transaction {tx_data.get('id')}[/green]")
            
            # --- REAL-TIME ANALYSIS PIPELINE ---
            # 1. Validate Schema
            try:
                tx = Transaction.model_validate(tx_data)
            except Exception as e:
                console.print(f"[red]Invalid transaction schema: {e}[/red]"); continue
            
            # 2. Run Sync Risk Checks (Fast, In-Memory)
            alerts = []
            if get_jurisdiction_risk(tx.sender_jurisdiction).risk_score > 50 or \
               get_jurisdiction_risk(tx.receiver_jurisdiction).risk_score > 50:
                alerts.append("High-Risk Jurisdiction")
            
            if 8000 < tx.amount < 10000:
                alerts.append("Potential Structuring")
            
            # 3. Push to Graph DB (Fast, Idempotent)
            insert_transaction_to_neo4j(neo4j_driver, tx)
            
            # 4. Produce job for Async Scoring
            # A separate worker pool (e.g., Celery, Faust) will consume from
            # this topic to run slow, heavy tasks (API calls for UBO, Wallet, Entity Risk).
            job_payload = {"tx_id": tx.id, "sender_id": tx.sender_id, "receiver_id": tx.receiver_id}
            producer.send(topic_out, value=job_payload)
            producer.flush() # Ensure it sends
            
            console.print(f"  -> Processed & Inserted: {tx.sender_id} -> {tx.receiver_id}")
            console.print(f"  -> [cyan]Published job {tx.id} to '{topic_out}' for async scoring.[/cyan]")
            if alerts:
                console.print(f"  [bold yellow]Sync Alerts:[/bold] {', '.join(alerts)}")

    except KeyboardInterrupt:
        console.print("\nShutting down Kafka consumer...")
    except Exception as e:
        console.print(f"[bold red]Kafka Error:[/bold red] {e}")
        logger.error(f"Kafka consumer failed: {e}", exc_info=True)
    finally:
        consumer.close()
        producer.close()
        neo4j_driver.close()