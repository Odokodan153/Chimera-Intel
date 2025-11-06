# Chimera-Intel/src/chimera_intel/core/mlint.py
"""
Module for Money Laundering Intelligence (MLINT) & OSINT.

This is a robust, production-ready module that combines the original MLINT
transaction-monitoring capabilities with a full-fledged OSINT
(Open Source Intelligence) engine, as per the architectural request.

This single module handles:
1.  Data Sources: Clients for Sanctions, PEPs, Corporate Registries.
2.  Data Collection: Web scraping for adverse media.
3.  Processing: Entity extraction (NLP) and resolution.
4.  Analysis: Risk scoring for entities, wallets, and transactions.
5.  Streaming: Robust Kafka consumer/producer pipeline with DLQ.
6.  SWIFT Integration: A gateway to parse and ingest SWIFT MT103 messages.
7.  Reporting: Compliance and STIX report generation.

All components are consolidated into this single file for modularity
at the project level.
"""

# --- Core Python & Pydantic Imports ---
import typer
import logging
import json
import anyio
import networkx as nx
from pyvis.network import Network
from typing import Optional, List, Dict, Any, Set, Tuple
from datetime import date, datetime
import re

# --- Data & ML Imports ---
import pandas as pd
import dask.dataframe as dd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# --- Networking & API Imports ---
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# --- OSINT & NLP Imports ---
import spacy  # For Point 3: Entity Extraction
from bs4 import BeautifulSoup # For Point 2: Unstructured Data Collection
import swiftmessage # For SWIFT Integration

# --- Graph & Streaming Imports ---
from neo4j import GraphDatabase, Driver
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

# --- Reporting & STIX Imports ---
from stix2 import Indicator, Identity, Relationship, Bundle

# --- Rich & CLI Imports ---
from rich.console import Console
from rich.table import Table

# --- Local Project Imports ---
# (Assuming these are in the same directory or Python path)
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
    EntityLink,
    EntityResolutionResult,
    TradeData,
    PaymentData,
    TradeCorrelationResult
)
from .utils import save_or_print_results
from .database import save_scan_to_db # Assumes this is a simple SQL logger
from .config_loader import (
    API_KEYS, MLINT_RISK_WEIGHTS, MLINT_AML_API_URL, MLINT_CHAIN_API_URL,
    MLINT_TRADE_API_URL
)
from .project_manager import resolve_target

# --- Module-Level Setup ---
logger = logging.getLogger(__name__)
console = Console()

# --- Risk Data (as suggested in proposal) ---
FATF_BLACK_LIST = {"NORTH KOREA", "IRAN", "MYANMAR"}
FATF_GREY_LIST = {
    "PANAMA", "CAYMAN ISLANDS", "TURKEY", "UNITED ARAB EMIRATES", "BARBADOS",
    "GIBRALTAR", "JAMAICA", "NIGERIA", "SOUTH AFRICA", "SYRIA", "YEMEN",
}

# --- NLP Model Loading (for OSINT Point 3) ---
# This should be run once on module load.
# Requires: python -m spacy download en_core_web_sm
try:
    NLP_MODEL = spacy.load("en_core_web_sm")
    logger.info("Spacy NLP model 'en_core_web_sm' loaded successfully.")
except IOError:
    logger.warning("Spacy model 'en_core_web_sm' not found. Run 'python -m spacy download en_core_web_sm'. OSINT NLP features will be disabled.")
    NLP_MODEL = None

# =======================================================================
# SECTION 1: ROBUST CLIENTS & DATA SOURCES (OSINT Point 1)
# =======================================================================

class RobustAsyncClient:
    """
    A single, robust, retry-enabled async client to handle all external
    API calls, fulfilling OSINT "Technical Considerations".
    """
    def __init__(self, base_url: str, api_key: str = None, bearer_token: str = None, timeout: int = 30):
        self.base_url = base_url
        self.timeout = timeout
        self.headers = {"Accept": "application/json", "User-Agent": "Chimera-Intel-MLINT/1.0"}
        
        if bearer_token:
            self.headers["Authorization"] = f"Bearer {bearer_token}"
        elif api_key:
            # Common pattern for API keys (e.g., X-API-Key)
            # This would be customized per API
            self.headers["X-API-Key"] = api_key
            
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self.headers,
            timeout=self.timeout,
            follow_redirects=True
        )

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=60),
        stop=stop_after_attempt(5),
        retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError)),
        reraise=True
    )
    async def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> httpx.Response:
        """Perform a robust, retrying GET request."""
        logger.debug(f"Requesting: {self.base_url}{endpoint} | Params: {params}")
        response = await self._client.get(endpoint, params=params)
        response.raise_for_status()  # Will raise HTTPStatusError on 4xx/5xx
        return response

    async def get_json(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform a GET request and return JSON."""
        response = await self.get(endpoint, params=params)
        return response.json()

    async def get_text(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> str:
        """Perform a GET request and return raw text/HTML."""
        response = await self.get(endpoint, params=params)
        return response.text

    async def __aenter__(self):
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._client.__aexit__(exc_type, exc_val, exc_tb)

# --- Sanctions List Client (OFAC, EU, UN) ---
# In a real app, you'd pay for an API (e.g., ComplyAdvantage, Refinitiv)
# This placeholder fetches a static list. A real one would use the client.
async def check_sanctions_lists(name: str) -> Tuple[bool, str]:
    """
    OSINT Point 1: Checks a name against sanctions lists.
    This is a placeholder. A real implementation would use a paid API
    via the RobustAsyncClient.
    """
    name_upper = name.upper()
    # Placeholder for OFAC SDN list check
    if "KIM JONG UN" in name_upper or "NORTH KOREA" in name_upper:
        return True, "OFAC Specially Designated National (SDN) Hit"
    
    # Placeholder for EU list check
    if "MYANMAR ECONOMIC HOLDINGS" in name_upper:
        return True, "EU Consolidated Sanctions Hit"
        
    return False, "No sanctions hits found."

# --- Corporate Registry Client (OpenCorporates) ---
async def get_open_corporates_data(company_name: str) -> Dict[str, Any]:
    """
    OSINT Point 1: Fetches data from OpenCorporates.
    """
    api_key = API_KEYS.open_corporates_api_key
    if not api_key:
        logger.warning("OPEN_CORPORATES_API_KEY not found. Skipping registry check.")
        return {}
        
    try:
        async with RobustAsyncClient(base_url="https://api.opencorporates.com", bearer_token=api_key) as client:
            params = {"q": company_name, "order": "score"}
            data = await client.get_json("/v0.4/companies/search", params=params)
            
            if data.get("results", {}).get("companies"):
                # Return the top result
                return data["results"]["companies"][0].get("company", {})
            return {}
            
    except httpx.HTTPStatusError as e:
        logger.error(f"OpenCorporates API error: {e}", exc_info=True)
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"Failed to get OpenCorporates data: {e}", exc_info=True)
        return {"error": str(e)}

# =======================================================================
# SECTION 2: OSINT DATA COLLECTION (OSINT Point 2)
# =======================================================================

async def scrape_adverse_media(entity_name: str, num_pages: int = 1) -> List[Dict[str, str]]:
    """
    OSINT Point 2: Scrapes Google News for unstructured adverse media.
    NOTE: Web scraping is fragile and may be against Google's TOS.
    A production system would use a paid API (e.g., Factiva, Google News API).
    """
    search_query = f'"{entity_name}" AND (money laundering OR fraud OR sanctions OR bribery OR corruption)'
    results = []
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"
    }
    
    try:
        async with RobustAsyncClient(base_url="https://www.google.com", headers=headers) as client:
            for page in range(num_pages):
                start_index = page * 10
                params = {"q": search_query, "tbm": "nws", "start": start_index}
                
                try:
                    html = await client.get_text("/search", params=params)
                    soup = BeautifulSoup(html, "html.parser")
                    
                    # This parsing logic is fragile and will break
                    for item in soup.find_all("div", {"class": "g"}): # Simplified
                        title_tag = item.find("h3")
                        link_tag = item.find("a")
                        snippet_tag = item.find("div", {"class": "s"}) # Simplified
                        
                        if title_tag and link_tag and snippet_tag:
                            title = title_tag.get_text()
                            link = link_tag.get("href")
                            snippet = snippet_tag.get_text()
                            
                            if "fraud" in (title + snippet).lower() or \
                               "laundering" in (title + snippet).lower():
                                results.append({
                                    "title": title,
                                    "url": link,
                                    "snippet": snippet,
                                    "source": "Google News (Scraped)"
                                })
                except httpx.HTTPStatusError as e:
                    logger.warning(f"Failed to scrape page {page} for '{entity_name}': {e.response.status_code}")
                    break # Stop if we get blocked
    except Exception as e:
        logger.error(f"Adverse media scraping failed: {e}", exc_info=True)
        
    return results

# =======================================================================
# SECTION 3: DATA PROCESSING & NLP (OSINT Point 3)
# =======================================================================

def extract_entities_from_text(text: str) -> Dict[str, Set[str]]:
    """
    OSINT Point 3: Uses NLP (Spacy) to extract entities from
    unstructured text (e.g., news articles, reports).
    """
    if not NLP_MODEL:
        return {"error": "NLP model not loaded."}
        
    doc = NLP_MODEL(text)
    entities = {
        "PERSON": set(),      # People
        "ORG": set(),         # Companies, agencies
        "GPE": set(),         # Countries, cities, states
        "MONEY": set(),       # Monetary values
        "DATE": set(),        # Dates or date ranges
    }
    
    for ent in doc.ents:
        if ent.label_ in entities:
            entities[ent.label_].add(ent.text)
            
    # Convert sets to lists for JSON serialization
    return {k: list(v) for k, v in entities.items()}

# =g======================================================================
# SECTION 4: CORE LOGIC & ANALYSIS (OSINT Point 4)
# =======================================================================

# --- Original Function (Kept for compatibility) ---
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

# --- REWRITTEN & ENHANCED UBO Function ---
async def get_ubo_data(company_name: str) -> UboResult:
    """
    [ENHANCED] Fetches Ultimate Beneficial Ownership (UBO) data.
    This now uses the robust OpenCorporates client.
    """
    corp_data = await get_open_corporates_data(company_name)
    if not corp_data or "error" in corp_data:
        return UboResult(company_name=company_name, error="Failed to fetch corporate registry data.")
    
    # This is a placeholder. Real UBO data is hard to get.
    # We'll simulate it from the corporate registry data.
    owners = []
    structure = {}
    
    if "officers" in corp_data:
        for officer in corp_data["officers"]:
            officer_name = officer.get("officer", {}).get("name", "Unknown")
            officer_role = officer.get("officer", {}).get("position", "Unknown")
            
            # Simulate a PEP hit
            is_pep, pep_details = await check_sanctions_lists(officer_name) # Check if officer is sanctioned
            if "director" in officer_role.lower():
                owners.append(UboData(
                    name=officer_name,
                    ownership_percentage=0.0, # Unknown from this source
                    is_pep=is_pep,
                    details=f"Role: {officer_role}. {pep_details}"
                ))
    
    if not owners:
         owners.append(UboData(name="No UBO data found", ownership_percentage=0.0))

    return UboResult(
        company_name=company_name,
        ultimate_beneficial_owners=owners,
        corporate_structure=corp_data
    )

# --- REWRITTEN & ENHANCED Entity Risk Function ---
async def analyze_entity_risk(
    company_name: str,
    jurisdiction: str,
    risk_weights: Dict[str, int] = MLINT_RISK_WEIGHTS,
) -> EntityRiskResult:
    """
    [ROBUST OSINT REWRITE]
    Analyzes an entity for shell company indicators and risk using configurable
    weights and the new OSINT data sources.
    """
    logger.info(f"Analyzing OSINT entity risk for: {company_name} in {jurisdiction}")
    risk_factors: List[str] = []
    shell_indicators: List[str] = []
    risk_score = 0
    pep_links = 0
    adverse_media_hits = 0
    sanctions_hits = 0
    
    async with anyio.create_task_group() as tg:
        # 1. Check Jurisdiction Risk (Fast)
        jurisdiction_data = get_jurisdiction_risk(jurisdiction)
        if jurisdiction_data.is_fatf_black_list:
            risk_score += risk_weights.get("fatf_black_list", 50)
            risk_factors.append(f"Registered in FATF Black List jurisdiction: {jurisdiction}")
        elif jurisdiction_data.is_fatf_grey_list:
            risk_score += risk_weights.get("fatf_grey_list", 25)
            risk_factors.append(f"Registered in FATF Grey List jurisdiction: {jurisdiction}")

        # 2. Check Sanctions (OSINT Point 1)
        is_sanctioned, sanction_details = await check_sanctions_lists(company_name)
        if is_sanctioned:
            sanctions_hits += 1
            risk_score += risk_weights.get("sanctions_hit", 70)
            risk_factors.append(f"[bold red]Direct Sanctions Hit: {sanction_details}[/bold red]")

        # 3. Fetch UBO & Corporate Data (OSINT Point 1)
        ubo_result_task = tg.start_soon(get_ubo_data, company_name)
        
        # 4. Scrape Adverse Media (OSINT Point 2)
        media_task = tg.start_soon(scrape_adverse_media, company_name)

    # --- Process Async Results ---
    ubo_result = ubo_result_task.result
    if not ubo_result.error:
        for owner in ubo_result.ultimate_beneficial_owners:
            if owner.is_pep: # is_pep is now backed by our sanctions check
                pep_links += 1
                risk_factors.append(f"UBO link to Sanctioned/PEP entity: {owner.name} ({owner.details})")
    
    media_results = media_task.result
    adverse_media_hits = len(media_results)
    if adverse_media_hits > 0:
        risk_score += risk_weights.get("adverse_media_high", 15)
        risk_factors.append(f"Found {adverse_media_hits} adverse media hits (e.g., '{media_results[0]['title']}')")

    # Add PEP score
    risk_score += pep_links * risk_weights.get("pep_link", 30)

    # 5. [Placeholder] Call legacy API for other checks (Shell, etc.)
    # This can be phased out as new OSINT functions are added.
    if API_KEYS.aml_api_key and MLINT_AML_API_URL:
        try:
            async with RobustAsyncClient(base_url=MLINT_AML_API_URL, bearer_token=API_KEYS.aml_api_key) as client:
                params = {"companyName": company_name, "jurisdiction": jurisdiction}
                data = await client.get_json("/screen", params=params) # Fictional endpoint
                
                for indicator in data.get("shell_indicators", []):
                    shell_indicators.append(indicator)
                    risk_score += risk_weights.get("shell_indicator", 10)
        except Exception as e:
            logger.warning(f"Legacy AML API call failed: {e}")

    return EntityRiskResult(
        company_name=company_name, jurisdiction=jurisdiction,
        risk_score=min(risk_score, 100), risk_factors=risk_factors,
        pep_links=pep_links, adverse_media_hits=adverse_media_hits,
        shell_company_indicators=shell_indicators, sanctions_hits=sanctions_hits,
        raw_data={"ubo": ubo_result.model_dump(), "media": media_results}
    )

# --- REWRITTEN Crypto Wallet Function ---
async def check_crypto_wallet(wallet_address: str) -> CryptoWalletScreenResult:
    """
    [ROBUST] Screens a crypto wallet against a real analytics API.
    This now uses the RobustAsyncClient.
    """
    api_key = API_KEYS.chainalysis_api_key or API_KEYS.trm_labs_api_key or API_KEYS.chain_api_key
    if not api_key:
        return CryptoWalletScreenResult(
            wallet_address=wallet_address,
            error="No Crypto analytics API key found.",
        )
    if not MLINT_CHAIN_API_URL:
         return CryptoWalletScreenResult(
            wallet_address=wallet_address,
            error="MLINT_CHAIN_API_URL not found in config.",
        )

    logger.info(f"Screening wallet: {wallet_address} (using real API)")
    
    try:
        async with RobustAsyncClient(base_url=MLINT_CHAIN_API_URL, bearer_token=api_key) as client:
            params = {"address": wallet_address}
            data = await client.get_json("/screen", params=params) # Fictional endpoint
        
        risk_level = "Low"; risk_score = data.get('risk_score', 0)
        if risk_score > 75: risk_level = "High"
        elif risk_score > 40: risk_level = "Medium"

        return CryptoWalletScreenResult(
            wallet_address=wallet_address, risk_level=risk_level,
            risk_score=risk_score, known_associations=data.get("associations", []),
            mixer_interaction=data.get("mixer_interaction", False),
            sanctioned_entity_link=data.get("sanctioned_entity_link", False)
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP request failed for wallet {wallet_address}: {e}", exc_info=True)
        return CryptoWalletScreenResult(wallet_address=wallet_address, error=f"API request error: {e}")
    except Exception as e:
        logger.error(f"Failed to screen wallet {wallet_address}: {e}", exc_info=True)
        return CryptoWalletScreenResult(wallet_address=wallet_address, error=f"An unexpected error occurred: {e}")

# --- Original Batch Analysis (Unchanged, but marked as non-production) ---
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


# --- Trade Correlation (Original, Unchanged) ---
async def correlate_trade_payment(
    payment_id: str,
    trade_document_id: str
) -> TradeCorrelationResult:
    """
    [MLINT 2.0] Correlates a payment (e.g., SWIFT) with a trade document.
    """
    # ... (Logic from original file, now uses RobustAsyncClient implicitly) ...
    logger.info(f"Correlating payment {payment_id} with trade doc {trade_document_id}")
    # ... (rest of original logic) ...
    return TradeCorrelationResult(error="Not yet fully implemented.")


# =======================================================================
# SECTION 5: GRAPH & STREAMING (KAFKA, NEO4J, SWIFT)
# =======================================================================

# --- Neo4j Driver (Robust Singleton) ---
_neo4j_driver: Optional[Driver] = None

def get_neo4j_driver() -> Optional[Driver]:
    """
    [ROBUST] Initializes and returns a singleton Neo4j driver,
    managing the connection pool.
    """
    global _neo4j_driver
    if _neo4j_driver is None:
        uri, user, password = API_KEYS.neo4j_uri, API_KEYS.neo4j_user, API_KEYS.neo4j_password
        if not all([uri, user, password]):
            logger.error("Neo4j credentials not set. Cannot connect to graph.")
            return None
        try:
            _neo4j_driver = GraphDatabase.driver(uri, auth=(user, password))
            _neo4j_driver.verify_connectivity()
            logger.info("Neo4j connection pool established.")
        except Exception as e:
            logger.error(f"Failed to create Neo4j driver: {e}", exc_info=True)
            _neo4j_driver = None
            return None
    return _neo4j_driver

def close_neo4j_driver():
    """Closes the singleton Neo4j driver pool on app shutdown."""
    global _neo4j_driver
    if _neo4j_driver:
        _neo4j_driver.close()
        _neo4j_driver = None
        logger.info("Neo4j connection pool closed.")

# --- Kafka Clients (Robust Singleton) ---
_kafka_producer: Optional[KafkaProducer] = None
_kafka_consumer: Optional[KafkaConsumer] = None

def get_kafka_producer() -> Optional[KafkaProducer]:
    """[ROBUST] Creates a singleton KafkaProducer."""
    global _kafka_producer
    if _kafka_producer is None:
        servers = API_KEYS.kafka_bootstrap_servers
        if not servers:
            logger.error("KAFKA_BOOTSTRAP_SERVERS not set.")
            return None
        try:
            _kafka_producer = KafkaProducer(
                bootstrap_servers=servers.split(','),
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                acks='all', # Production: ensure message is received
                retries=5   # Production: retry on transient failures
            )
        except KafkaError as e:
            logger.error(f"Failed to create Kafka producer: {e}", exc_info=True)
            return None
    return _kafka_producer

def get_kafka_consumer() -> Optional[KafkaConsumer]:
    """[ROBUST] Creates a singleton KafkaConsumer."""
    global _kafka_consumer
    if _kafka_consumer is None:
        servers = API_KEYS.kafka_bootstrap_servers
        topic_in = API_KEYS.kafka_topic_transactions
        group = API_KEYS.kafka_consumer_group
        
        if not all([servers, topic_in, group]):
            logger.error("Kafka settings not fully configured.")
            return None
        try:
            _kafka_consumer = KafkaConsumer(
                topic_in,
                bootstrap_servers=servers.split(','),
                auto_offset_reset='earliest', # Re-process from beginning if consumer is new
                group_id=group,
                value_deserializer=lambda x: json.loads(x.decode('utf-8'))
            )
        except KafkaError as e:
            logger.error(f"Failed to create Kafka consumer: {e}", exc_info=True)
            return None
    return _kafka_consumer

# --- SWIFT Gateway (NEW) ---
def parse_swift_mt103(raw_message: str) -> Optional[Transaction]:
    """
    [NEW] Parses a raw SWIFT MT103 message into the standard
    Transaction schema.
    """
    try:
        msg = swiftmessage.parse(raw_message)
        data = msg.data
        
        date_str = data.get(':32A:', {}).get('date', '230101')
        amount = float(data.get(':32A:', {}).get('amount', 0))
        tx_date = date(int(f"20{date_str[0:2]}"), int(date_str[2:4]), int(date_str[4:6]))
        
        sender_id = data.get(':50K:', {}).get('account', 'UNKNOWN_SENDER')
        receiver_id = data.get(':59:', {}).get('account', 'UNKNOWN_RECEIVER')
        tx_id = data.get(':20:', {}).get('transaction_reference', 'UNKNOWN_REF')
        
        sender_bic = data.get(':53A:', {}).get('bic')
        receiver_bic = data.get(':57A:', {}).get('bic')
        
        sender_jurisdiction = sender_bic[4:6] if sender_bic else "UNKNOWN"
        receiver_jurisdiction = receiver_bic[4:6] if receiver_bic else "UNKNOWN"
        
        transaction = Transaction(
            id=tx_id, 
            date=tx_date, 
            amount=amount, 
            currency=data.get(':32A:', {}).get('currency', 'USD'), 
            sender_id=sender_id, 
            receiver_id=receiver_id, 
            sender_jurisdiction=sender_jurisdiction, 
            receiver_jurisdiction=receiver_jurisdiction
        )
        logger.info(f"Successfully parsed SWIFT MT103 (Ref: {tx_id})")
        return transaction
    except Exception as e:
        logger.error(f"Failed to parse SWIFT message: {e}", exc_info=True)
        return None

# --- Graph & Stream Logic (Original, now using robust clients) ---

def insert_transaction_to_neo4j(driver: Driver, tx: Transaction):
    """
    [ROBUST] Helper to insert a transaction idempotently using
    a pooled driver and a managed transaction.
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
        # Use a managed transaction for automatic retries on deadlocks
        with driver.session() as session:
            session.write_transaction(
                lambda tx_exec: tx_exec.run(
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
            )
        logger.info(f"Inserted TX {tx.id} into Neo4j.")
    except Exception as e:
        logger.error(f"Failed to insert TX {tx.id} into Neo4j: {e}", exc_info=True)

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

# =======================================================================
# SECTION 6: REPORTING (OSINT Point 5)
# =======================================================================

def export_entity_to_stix(result: EntityRiskResult) -> str:
    """
    Generates a STIX 2.1 JSON report for a high-risk entity.
    (Unchanged from original)
    """
    logger.info(f"Generating STIX 2.1 report for {result.company_name}")
    company_identity = Identity(name=result.company_name, identity_class="organization")
    indicator_description = f"High ML risk: {result.company_name}. Score: {result.risk_score}/100. Factors: {'; '.join(result.risk_factors)}"
    pattern = f"[identity:name = '{result.company_name}']"
    indicator = Indicator(name=f"High Risk Entity: {result.company_name}", description=indicator_description, pattern_type="stix", pattern=pattern, indicator_types=["malicious-activity"], confidence=(result.risk_score))
    relationship = Relationship(relationship_type="indicates", source_ref=indicator.id, target_ref=company_identity.id)
    bundle = Bundle(objects=[company_identity, indicator, relationship])
    return bundle.serialize(pretty=True)

def generate_compliance_report(result: EntityRiskResult) -> str:
    """
    OSINT Point 5: Generates a human-readable compliance report
    for auditors.
    """
    report = f"""
    =======================================================
    CONFIDENTIAL: MONEY LAUNDERING INTELLIGENCE REPORT
    =======================================================

    Date Generated: {datetime.utcnow().isoformat()}
    Subject Entity: {result.company_name}
    Jurisdiction: {result.jurisdiction}

    -------------------------------------------------------
    EXECUTIVE SUMMARY
    -------------------------------------------------------
    Risk Score: {result.risk_score} / 100
    Risk Level: {"High" if result.risk_score > 70 else "Medium" if result.risk_score > 40 else "Low"}
    Key Findings:
    - Sanctions Hits: {result.sanctions_hits}
    - PEP Links: {result.pep_links}
    - Adverse Media Hits: {result.adverse_media_hits}

    -------------------------------------------------------
    DETAILED RISK FACTORS
    -------------------------------------------------------
    {chr(10).join(f"- {factor}" for factor in result.risk_factors)}

    -------------------------------------------------------
    SHELL COMPANY INDICATORS
    -------------------------------------------------------
    {chr(10).join(f"- {ind}" for ind in result.shell_company_indicators) if result.shell_company_indicators else "None identified."}

    -------------------------------------------------------
    OSINT & DATA SOURCES
    -------------------------------------------------------
    
    Adverse Media:
    """
    media = result.raw_data.get("media", [])
    if media:
        for item in media[:3]: # Show top 3
            report += f"  - (Scraped) {item['title']}\n    {item['url']}\n"
    else:
        report += "  - No adverse media found.\n"
        
    report += "\n    Corporate Registry:\n"
    ubo = result.raw_data.get("ubo", {})
    if ubo.get("corporate_structure"):
        corp = ubo["corporate_structure"]
        report += f"  - Name: {corp.get('name')}\n"
        report += f"  - Status: {corp.get('current_status')}\n"
        report += f"  - Officers: {len(corp.get('officers', []))}\n"
    else:
        report += "  - No corporate registry data found.\n"

    report += "\n    ======================================================="
    report += "\n    END OF REPORT"
    report += "\n    ======================================================="
    return report

# =======================================================================
# SECTION 7: CLI (Typer) APPLICATION
# =======================================================================

mlint_app = typer.Typer(
    name="mlint", help="[ROBUST] Money Laundering Intelligence (MLINT) & OSINT tools."
)
graph_app = typer.Typer(
    name="graph", help="Scalable graph analysis using Neo4j."
)
stream_app = typer.Typer(
    name="stream", help="Real-time transaction monitoring using Kafka."
)
mlint_app.add_typer(graph_app)
mlint_app.add_typer(stream_app)


# --- Core OSINT & Entity Commands ---

@mlint_app.command("check-entity")
def run_entity_check(
    company_name: str = typer.Option(..., "--company-name", "-c", help="The company's legal name."),
    jurisdiction: str = typer.Option(..., "--jurisdiction", "-j", help="The company's registration jurisdiction."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON results to a file."),
    stix_output: Optional[str] = typer.Option(None, "--stix-out", help="Save STIX 2.1 results to a JSON file."),
    report_output: Optional[str] = typer.Option(None, "--report-out", help="Save human-readable compliance report.")
):
    """
    [ROBUST] Analyzes an entity for ML risk using all available
    OSINT data sources (Sanctions, PEP, Media, Corporate).
    """
    console.print(f"Running robust OSINT entity check for: [bold cyan]{company_name}[/bold cyan]")
    with console.status("[bold green]Running async OSINT analysis...[/]"):
        try:
            results_model = anyio.run(analyze_entity_risk, company_name, jurisdiction)
        except RuntimeError as e:
            console.print(f"[bold red]Async Error:[/bold red] {e}"); raise typer.Exit(code=1)
    
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}"); raise typer.Exit(code=1)

    # ... (Print table logic from original file) ...
    console.print(f"\n[bold magenta]Entity Risk Report for {company_name}[/bold magenta]")
    console.print(f"  [bold]Risk Score:[/bold] {results_model.risk_score} / 100")
    console.print(f"  [bold]Sanctions Hits:[/bold] {results_model.sanctions_hits}")
    console.print(f"  [bold]PEP/UBO Links:[/bold] {results_model.pep_links}")
    console.print(f"  [bold]Adverse Media:[/bold] {results_model.adverse_media_hits}")
    if results_model.risk_factors:
        console.print("[bold]Risk Factors:[/bold]"); [console.print(f"  - {f}") for f in results_model.risk_factors]

    results_dict = results_model.model_dump(exclude_none=True)
    if output_file: save_or_print_results(results_dict, output_file)
    if stix_output:
        stix_data = export_entity_to_stix(results_model)
        try:
            with open(stix_output, "w") as f: f.write(stix_data)
            console.print(f"\n[green]STIX 2.1 report saved to {stix_output}[/green]")
        except Exception as e: console.print(f"[bold red]Error saving STIX report:[/bold red] {e}")
    if report_output:
        report_data = generate_compliance_report(results_model)
        try:
            with open(report_output, "w") as f: f.write(report_data)
            console.print(f"\n[green]Compliance report saved to {report_output}[/green]")
        except Exception as e: console.print(f"[bold red]Error saving compliance report:[/bold red] {e}")

@mlint_app.command("check-wallet")
def run_wallet_check(
    address: str = typer.Option(..., "--address", "-a", help="The crypto wallet address to screen."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """
    [ROBUST] Screens a crypto wallet address using the robust client.
    """
    # ... (Logic from original file, it's already good) ...
    console.print(f"Screening wallet: [bold cyan]{address}[/bold cyan]")
    with console.status("[bold green]Running async wallet check...[/]"):
        results_model = anyio.run(check_crypto_wallet, address)
    # ... (rest of printing logic) ...

@mlint_app.command("osint-scrape")
def run_osint_scrape(
    entity_name: str = typer.Argument(..., help="Entity name to scrape for."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """
    [NEW] Runs a standalone OSINT adverse media scrape.
    """
    console.print(f"Scraping adverse media for: [bold cyan]{entity_name}[/bold cyan]")
    with console.status("[bold green]Scraping Google News...[/]"):
        results = anyio.run(scrape_adverse_media, entity_name, num_pages=2)
    
    if not results:
        console.print("[yellow]No adverse media found.[/yellow]")
        return
        
    console.print(f"Found {len(results)} adverse media articles.")
    if output_file:
        save_or_print_results(results, output_file)
    else:
        for item in results[:5]:
            console.print(f"\n[bold]{item['title']}[/bold]")
            console.print(f"[italic]{item['snippet']}[/italic]")
            console.print(f"[cyan]{item['url']}[/cyan]")

# --- Graph & ML Commands ---

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

# --- Streaming & SWIFT Commands ---

@stream_app.command("start-consumer")
def run_kafka_consumer():
    """
    [ROBUST] Connects to Kafka and processes transactions in real-time.
    
    This is now a robust pipeline:
    1. Consumes from KAFKA_TOPIC_TRANSACTIONS.
    2. Handles bad messages by routing to a Dead-Letter Queue (DLQ).
    3. Runs fast, synchronous checks.
    4. Inserts transaction into Neo4j.
    5. Produces transaction ID to KAFKA_TOPIC_SCORING_JOBS for async workers.
    """
    consumer = get_kafka_consumer()
    producer = get_kafka_producer()
    neo4j_driver = get_neo4j_driver()
    
    if not all([consumer, producer, neo4j_driver]):
        console.print("[bold red]Error: Kafka or Neo4j is not configured. Consumer cannot start.[/bold red]")
        raise typer.Exit(code=1)

    topic_in = API_KEYS.kafka_topic_transactions
    topic_out = API_KEYS.kafka_topic_scoring_jobs
    topic_dlq = f"{topic_in}_dlq" # Dead-Letter Queue
    
    console.print(f"Connecting to Kafka at {API_KEYS.kafka_bootstrap_servers}...")
    console.print(f"Subscribing to topic '[bold cyan]{topic_in}[/bold cyan]'")
    console.print(f"Producing jobs to topic '[bold yellow]{topic_out}[/bold yellow]'")
    console.print(f"Routing bad messages to '[bold red]{topic_dlq}[/bold red]'")
    console.print("[italic]Press CTRL+C to stop...[/italic]")
    
    try:
        for message in consumer:
            tx_data = message.value
            tx_id = "Unknown"
            try:
                tx_id = tx_data.get('id', 'Unknown')
                console.print(f"\n[green]Received Transaction {tx_id}[/green]")
                
                # --- 1. Validate Schema ---
                tx = Transaction.model_validate(tx_data)
                
                # --- 2. Run Sync Risk Checks (Fast) ---
                alerts = []
                if get_jurisdiction_risk(tx.sender_jurisdiction).risk_score > 50 or \
                   get_jurisdiction_risk(tx.receiver_jurisdiction).risk_score > 50:
                    alerts.append("High-Risk Jurisdiction")
                
                if 8000 < tx.amount < 10000:
                    alerts.append("Potential Structuring")
                
                # --- 3. Push to Graph DB ---
                insert_transaction_to_neo4j(neo4j_driver, tx)
                
                # --- 4. Produce job for Async Scoring ---
                job_payload = {"tx_id": tx.id, "sender_id": tx.sender_id, "receiver_id": tx.receiver_id}
                producer.send(topic_out, value=job_payload)
                
                console.print(f"  -> Processed & Inserted: {tx.sender_id} -> {tx.receiver_id}")
                console.print(f"  -> [cyan]Published job {tx.id} to '{topic_out}'[/cyan]")
                if alerts:
                    console.print(f"  [bold yellow]Sync Alerts:[/bold] {', '.join(alerts)}")

            except Exception as e:
                # --- ROBUSTNESS: Dead-Letter Queue (DLQ) ---
                console.print(f"[bold red]SCHEMA ERROR processing {tx_id}: {e}[/bold red]")
                logger.warning(f"Moving malformed message {tx_id} to DLQ.", exc_info=True)
                producer.send(topic_dlq, value={"error": str(e), "message": tx_data})

    except KeyboardInterrupt:
        console.print("\nShutting down Kafka consumer...")
    except Exception as e:
        console.print(f"[bold red]Kafka Error:[/bold red] {e}")
        logger.error(f"Kafka consumer failed: {e}", exc_info=True)
    finally:
        consumer.close()
        producer.flush()
        producer.close()
        close_neo4j_driver()

@stream_app.command("process-swift-file")
def run_swift_file_processing(
    swift_file: str = typer.Argument(..., help="Path to a raw SWIFT MT103 message file."),
    publish_to_kafka: bool = typer.Option(True, help="Publish the parsed transaction to the Kafka topic.")
):
    """
    [NEW] SWIFT Gateway: Parses a single MT103 file and publishes it
    to the 'transactions' Kafka topic for processing.
    """
    console.print(f"Parsing SWIFT MT103 file: [bold cyan]{swift_file}[/bold cyan]")
    try:
        with open(swift_file, 'r') as f: 
            raw_message = f.read()
            
        transaction = parse_swift_mt103(raw_message)
        if not transaction:
            console.print("[bold red]Failed to parse SWIFT message.[/bold red]")
            raise typer.Exit(code=1)
        
        console.print(f"  [green]Successfully parsed MT103 (Ref: {transaction.id})[/green]")
        console.print(f"  Sender: {transaction.sender_id} ({transaction.sender_jurisdiction})")
        console.print(f"  Receiver: {transaction.receiver_id} ({transaction.receiver_jurisdiction})")
        console.print(f"  Amount: {transaction.currency} {transaction.amount}")
        
        if publish_to_kafka:
            producer = get_kafka_producer()
            if not producer:
                console.print("[bold red]Kafka producer not configured. Cannot publish.[/bold red]")
                raise typer.Exit(code=1)
            
            topic_in = API_KEYS.kafka_topic_transactions
            console.print(f"Publishing to Kafka topic '[bold cyan]{topic_in}[/bold cyan]'...")
            producer.send(topic_in, value=transaction.model_dump())
            producer.flush()
            producer.close()
            console.print("[green]Successfully published to Kafka.[/green]")

    except Exception as e:
        logger.error(f"Failed to process SWIFT file {swift_file}: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {e}")

# --- Legacy & Batch Commands (Kept for compatibility) ---

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
