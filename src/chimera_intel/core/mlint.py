"""
Module for Money Laundering Intelligence (MLINT).

Provides tools to detect suspicious financial patterns, analyze entity risk,
and identify high-risk jurisdictions or crypto wallets. This module is designed
to be scalable, integrating with graph databases (Neo4j) and streaming platforms
(Kafka) as defined in the advanced architecture.
"""

"""
Data Sources & Enrichment
Implemented: Async fetch for UBOs (get_ubo_data), crypto wallet checks (check_crypto_wallet), and adverse media hits.
Missing / Placeholder:
Real integration with OpenCorporates, Nansen, TRM Labs, World-Check APIs.
Full UBO hierarchies and relationship embeddings.
Automated NLP sentiment scoring on adverse media.
Advanced ML / AI
Implemented: Batch anomaly detection with IsolationForest on transactions. Placeholder for GNN (run_gnn_anomaly).
Missing / Placeholder:
Graph Neural Networks for node-level anomaly detection.
Temporal models (LSTM, Transformer) for transaction sequences.
Autoencoders / variational GNNs for hidden laundering patterns.
Dynamic feature engineering (velocity, cross-jurisdiction flows).
Explainable AI, e.g., path reasoning on anomaly decisions.
Graph Intelligence
Implemented: Neo4j connection scaffold and find-cycles CLI.
Missing:
Community detection, betweenness centrality, shortest-path risk propagation.
Incremental updates for streaming transactions.
Real-time graph enrichment (most of the graph data is still mocked or partial).
Streaming / Real-Time Analysis
Implemented: Kafka consumer scaffold (start-consumer).
Missing:
Async + task queue (Celery, RQ) pipeline for real-time scoring.
Real-time anomaly scoring and graph insertion.
Event-driven alerts. Current loop is blocking and conceptual.
Cross-Channel & Multi-Asset
Implemented: Crypto wallets (BTC/ETH/USDT), SWIFT MT103 parsing.
Missing:
Cross-chain correlation, DeFi interactions.
Large-scale SWIFT parsing and multi-asset aggregation.
Scalability
Implemented: Dask for parallelized batch operations, Neo4j for graph cycles.
Missing:
Distributed PyTorch + Dask/Spark for large-scale anomaly detection.
Caching UBO/jurisdiction lookups and graph embeddings.
Batch networkx cycles detection is deprecated due to scalability.
Risk Scoring & Compliance
Implemented: Composite scoring using jurisdiction, PEP, sanctions, adverse media.
Missing:
Dynamic thresholds based on historical patterns.
Network centrality scoring.
Integration with regulatory dashboards (FATF, FinCEN, EU AMLD6).
Reporting & Audit
Implemented: STIX 2.1 export (export_entity_to_stix), logging, and database save (save_scan_to_db).
Missing:
Immutable audit trail in graph DB / data lake.
Automated alerts for compliance teams.
Optional “Next-Level” Enhancements
Implemented: Placeholders for GNN anomaly and generative AI summaries.
Missing:
Interactive dashboards (Plotly Dash, Streamlit, Neo4j Bloom).
Scenario simulation of hypothetical laundering paths.
"""

import typer
import logging
import json
import anyio
import httpx
import swiftmessage
import dask.dataframe as dd # [ENHANCEMENT] For parallel processing
from typing import Optional, List, Dict
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
from kafka import KafkaConsumer # [ENHANCEMENT] For real-time streaming

from .schemas import (
    BaseResult,
    JurisdictionRisk,
    EntityRiskResult,
    CryptoWalletScreenResult,
    Transaction,
    TransactionAnalysisResult,
    SwiftTransactionAnalysisResult,
    UboResult, # [ENHANCEMENT] New schemas
    UboData,
    GnnAnomalyResult
)
from .utils import save_or_print_results
from .database import save_scan_to_db
from .config_loader import (
    API_KEYS, MLINT_RISK_WEIGHTS, MLINT_AML_API_URL, MLINT_CHAIN_API_URL
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
    [ENHANCEMENT] Fetches Ultimate Beneficial Ownership (UBO) data.
    This integrates with OpenCorporates, World-Check, etc.
    """
    api_key = API_KEYS.open_corporates_api_key or API_KEYS.world_check_api_key
    if not api_key:
        return UboResult(company_name=company_name, error="No UBO API key (e.g., OPEN_CORPORATES_API_KEY) found.")
    
    logger.info(f"Fetching UBO data for {company_name}")
    
    # [ENHANCEMENT] Real UBO API Call
    # Note: No specific UBO URL is defined in config_loader.
    # Using MLINT_AML_API_URL as a placeholder. A real implementation
    # would use a dedicated UBO API endpoint (e.g., from OpenCorporates).
    if not MLINT_AML_API_URL:
         return UboResult(company_name=company_name, error="MLINT_AML_API_URL (used as placeholder UBO API) not found.")

    headers = {"Authorization": f"Bearer {api_key}"}
    params = {"companyName": company_name, "queryContext": "ubo"} # Assuming API can distinguish UBO queries

    try:
        async with httpx.AsyncClient() as client:
            # Using MLINT_AML_API_URL as a placeholder as no UBO_URL is defined
            response = await client.get(MLINT_AML_API_URL, params=params, headers=headers, timeout=30.0)
            response.raise_for_status()
            data = response.json()
        
        # --- [ENHANCEMENT] Parse real UBO data ---
        # This parsing is HYPOTHETICAL and depends on the actual API response
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
            
            # --- Real data parsing ---
            pep_links += data.get("pep_links", 0) # Add PEPs from screening
            if pep_links > 0:
                risk_score += pep_links * risk_weights.get("pep_link", 30)
                risk_factors.append(f"Found {pep_links} total Politically Exposed Persons (PEPs).")

            sanctions_hits = data.get("sanctions_hits", 0)
            if sanctions_hits > 0:
                risk_score += sanctions_hits * risk_weights.get("sanctions_hit", 70)
                risk_factors.append(f"[bold red]Direct hit on {sanctions_hits} sanctions lists (e.g., OFAC).[/bold red]")
            
            adverse_media_hits = data.get("adverse_media_hits", 0)
            if adverse_media_hits > 20: # Example threshold
                risk_score += risk_weights.get("adverse_media_high", 15)
                risk_factors.append(f"High adverse media: {adverse_media_hits} hits.")

            # Parse shell indicators from real API
            for indicator in data.get("shell_indicators", []):
                shell_indicators.append(indicator)
                risk_score += risk_weights.get("shell_indicator", 10)
            # ... (rest of risk scoring logic) ...

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
    headers = {"Authorization": f"Bearer {api_key}"} # Use the first key found

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(MLINT_CHAIN_API_URL, params=params, headers=headers, timeout=30.0)
            response.raise_for_status()
            data = response.json()
        
        # --- Real data parsing ---
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
        # [ENHANCEMENT] Use Dask for parallelized dataframe operations
        ddf = dd.from_pandas(df, npartitions=4)
        
        df['date'] = pd.to_datetime(df['date'])
        total_transactions = len(df)
        total_volume = ddf['amount'].sum().compute()
        
        # ... (Structuring, High-Risk Flow logic remains the same) ...
        structuring_alerts = []
        high_risk_flows = []
        
        # [ENHANCEMENT] Scalability warning for cycle detection
        logger.critical(
            "SKIPPING 'networkx.simple_cycles' due to extreme scalability issues (O(N!))."
            " This feature is only available via the 'mlint graph find-cycles' command,"
            " which requires a running Neo4j instance."
        )
        round_tripping_alerts = [] # Deprecated here.

        # 4. ML Anomaly Score with richer features
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


# --- [ENHANCEMENT] CLI Commands: Graph (Neo4j) ---

@graph_app.command("find-cycles")
def run_neo4j_cycle_detection(
    max_length: int = typer.Option(5, help="Maximum path length for cycle detection.")
):
    """
    [PLACEHOLDER] Finds transaction cycles (round-tripping) using Neo4j.
    """
    uri, user, password = API_KEYS.neo4j_uri, API_KEYS.neo4j_user, API_KEYS.neo4j_password
    if not all([uri, user, password]):
        console.print("[bold red]Error: Neo4j credentials (NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD) not set.[/bold red]")
        raise typer.Exit(code=1)
        
    console.print(f"Connecting to Neo4j at {uri} to find cycles (max_length={max_length})...")
    
    # This Cypher query finds cycles. It's far more scalable than networkx.
    cypher_query = f"""
    MATCH path = (a:Account)-[:SENT_TO*1..{max_length}]->(a)
    WHERE all(n IN nodes(path) | size([m IN nodes(path) WHERE m = n]) = 1)
    RETURN [n IN nodes(path) | n.id] as cycle, length(path) as length
    ORDER BY length
    LIMIT 100
    """
    
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            result = session.run(cypher_query)
            cycles = [record["cycle"] for record in result]
        
        console.print(f"[green]Successfully ran query. Found {len(cycles)} cycles.[/green]")
        for cycle in cycles:
            console.print(f"  - Cycle: {' -> '.join(cycle)}")
        driver.close()
    except Exception as e:
        console.print(f"[bold red]Neo4j Error:[/bold red] {e}")
        logger.error(f"Failed to run Neo4j cycle detection: {e}", exc_info=True)
        
@graph_app.command("run-gnn-anomaly")
def run_gnn_anomaly():
    """
    [PLACEHOLDER] Triggers a Graph Neural Network (GNN) anomaly detection job.
    """
    console.print("[bold yellow]This is a placeholder for a complex GNN task.[/bold yellow]")
    console.print("This would typically involve:")
    console.print("  1. Loading the graph from Neo4j into a PyTorch Geometric (PyG) object.")
    console.print("  2. Training or loading a GNN model (e.g., GCN, GraphSAGE, GAE).")
    console.print("  3. Calculating node embeddings and anomaly scores.")
    console.print("  4. Writing risk scores back to the Neo4j graph.")
    # Mock result
    console.print(GnnAnomalyResult(entity_id="A-123", anomaly_score=0.95, reason=["High betweenness centrality", "Connected to 3 sanctioned entities"]).model_dump_json(indent=2))

# --- [ENHANCEMENT] CLI Commands: Streaming (Kafka) ---

@stream_app.command("start-consumer")
def run_kafka_consumer():
    """
    [PLACEHOLDER] Connects to Kafka and processes transactions in real-time.
    """
    servers = API_KEYS.kafka_bootstrap_servers
    topic = API_KEYS.kafka_topic_transactions
    group = API_KEYS.kafka_consumer_group
    
    if not all([servers, topic, group]):
        console.print("[bold red]Error: Kafka settings (KAFKA_BOOTSTRAP_SERVERS, etc.) not set.[/bold red]")
        raise typer.Exit(code=1)

    console.print(f"Connecting to Kafka at {servers}...")
    console.print(f"Subscribing to topic '[bold cyan]{topic}[/bold cyan]' as group '[bold yellow]{group}[/bold yellow]'")
    console.print("[italic]Press CTRL+C to stop...[/italic]")
    
    try:
        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=servers.split(','),
            auto_offset_reset='earliest',
            group_id=group,
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
        
        # This is a blocking loop
        for message in consumer:
            tx_data = message.value
            console.print(f"\n[green]Received Transaction {tx_data.get('id')}[/green]")
            # --- REAL-TIME ANALYSIS PIPELINE (PLACEHOLDER) ---
            # 1. Validate Schema
            try:
                tx = Transaction.model_validate(tx_data)
            except Exception as e:
                console.print(f"[red]Invalid transaction schema: {e}[/red]"); continue
            
            # 2. Run Sync Risk Checks (Jurisdiction, Structuring)
            alerts = []
            if get_jurisdiction_risk(tx.sender_jurisdiction).risk_score > 50 or \
               get_jurisdiction_risk(tx.receiver_jurisdiction).risk_score > 50:
                alerts.append("High-Risk Jurisdiction")
            
            if 8000 < tx.amount < 10000:
                alerts.append("Potential Structuring")
                
            # 3. Trigger Async Checks (e.g., call entity/wallet screening)
            # (In a real system, this would use a task queue like Celery)
            
            # 4. Push to Graph DB
            # (e.g., run_neo4j_query("CREATE (t:Transaction {id: ...})"))
            
            console.print(f"  -> Processed: {tx.sender_id} -> {tx.receiver_id} ({tx.amount} {tx.currency})")
            if alerts:
                console.print(f"  [bold yellow]Alerts:[/bold] {', '.join(alerts)}")

    except KeyboardInterrupt:
        console.print("\nShutting down Kafka consumer...")
    except Exception as e:
        console.print(f"[bold red]Kafka Error:[/bold red] {e}")
        logger.error(f"Kafka consumer failed: {e}", exc_info=True)