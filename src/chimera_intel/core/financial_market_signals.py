"""
Core logic and CLI for Financial & Market Signals.
(This file holds the implementation imported by main.py)
"""
import spacy
import networkx as nx
import numpy as np
import json
import typer
from spacy.matcher import Matcher
from typing import List, Dict
from .schemas import (FinancialDocument, 
                      NlpSignal,
                      ShippingRecord,
                      Invoice,
                      TradeMatch,
                      FundingEvent,
                      FundingAnomaly,
                      Transaction,
                      PaymentFlowCorrelation)

from datetime import datetime
from thefuzz import fuzz
from rich.console import Console
from rich.table import Table
from pathlib import Path


class FinancialMarketSignalAnalyzer:
    """
    (UPDATED from core)
    Analyzes financial documents, trade data, funding platforms, and payment flows
    using NLP, graph analysis, and statistical methods.
    """

    def __init__(self):
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            print(
                "Error: spaCy model 'en_core_web_sm' not found. "
                "Please run: python -m spacy download en_core_web_sm"
            )
            self.nlp = None
            return
        
        # Add a sentencizer for textblob sentiment, as it works per-sentence
        if not self.nlp.has_pipe("sentencizer") and not self.nlp.has_pipe("parser"):
             self.nlp.add_pipe("sentencizer")

        # Use a more modern/performant sentiment pipe if available
        # For this example, we'll add spacytextblob for simplicity
        if not self.nlp.has_pipe("spacytextblob"):
             self.nlp.add_pipe("spacytextblob")
        
        self.matcher = Matcher(self.nlp.vocab)
        self.setup_matchers()
        print("FinancialMarketSignalAnalyzer initialized with real NLP and analysis tools.")

    def setup_matchers(self):
        """
        (UPDATED from core)
        Set up spaCy Matcher patterns for topics and risks.
        """
        if not self.nlp:
            return
            
        # Risk patterns
        risk_patterns = [
            [{"LOWER": "regulatory"}, {"LOWER": "scrutiny"}],
            [{"LOWER": "litigation"}],
            [{"LOWER": "market"}, {"LOWER": "risk"}],
            [{"LOWER": "headwinds"}],
            [{"LOWER": "fraud"}],
            [{"LOWER": "investigation"}],
            [{"LOWER": "sec"}, {"LOWER": "inquiry"}],
            [{"LOWER": "compliance"}, {"LOWER": "failure"}],
            [{"LOWER": "material"}, {"LOWER": "weakness"}],
            [{"LOWER": "supply"}, {"LOWER": "chain"}, {"LOWER": "disruption"}],
            [{"LOWER": "data"}, {"LOWER": "breach"}],
            [{"LOWER": "cybersecurity"}, {"LOWER": "incident"}],
            [{"LOWER": "economic"}, {"LOWER": "downturn"}],
            [{"LOWER": "geopolitical"}, {"LOWER": "risk"}],
            [{"LOWER": "unfavorable"}, {"LOWER": "ruling"}]
        ]
        self.matcher.add("RISK_FACTORS", risk_patterns)

        # Topic patterns (M&A, Expansion, CapEx, Leadership)
        topic_patterns = [
            [{"LOWER": "merger"}],
            [{"LOWER": "acquisition"}],
            [{"LOWER": "acquiring"}],
            [{"LOWER": "proposes"}, {"LOWER": "to"}, {"LOWER": "buy"}],
            [{"LOWER": "new"}, {"LOWER": "market"}],
            [{"LOWER": "launching"}],
            [{"LOWER": "expansion"}, {"LOWER": "into"}],
            [{"LOWER": "opens"}, {"LOWER": "new"}, {"LOWER": "facility"}],
            [{"LOWER": "capital"}, {"LOWER": "expenditure"}],
            [{"LOWER": "investing"}, {"LOWER": "in"}, {"LOWER": "infrastructure"}],
            [{"LOWER": "new"}, {"LOWER": "ceo"}],
            [{"LOWER": "cfo"}, {"LOWER": "resigns"}],
            [{"LOWER": "appoints"}, {"LOWER": "new"}, {"LOWER": "president"}],
            [{"LOWER": "leadership"}, {"LOWER": "transition"}]
        ]
        self.matcher.add("KEY_TOPICS", topic_patterns)

    def extract_signals_from_document(self, doc: FinancialDocument) -> NlpSignal:
        """
        (UPDATED from core)
        Uses spaCy for robust NLP (Sentiment, NER, Topic/Risk Matching).
        """
        if not self.nlp:
            return NlpSignal(doc.doc_id, "neutral", [], [], {})

        nlp_doc = self.nlp(doc.content)
        
        # 1. Sentiment Analysis
        polarity = nlp_doc._.blob.polarity
        if polarity > 0.1:
            sentiment = "positive"
        elif polarity < -0.1:
            sentiment = "negative"
        else:
            sentiment = "neutral"

        # 2. Risk Factor & Topic Extraction
        matches = self.matcher(nlp_doc)
        risks = set()
        topics = set()
        for match_id, start, end in matches:
            span = nlp_doc[start:end].text.lower()
            rule_id = self.nlp.vocab.strings[match_id]
            if rule_id == "RISK_FACTORS":
                risks.add(span)
            elif rule_id == "KEY_TOPICS":
                # Normalize topics
                if span in ["merger", "acquisition", "acquiring", "proposes to buy"]:
                    topics.add("M&A")
                elif span in ["new market", "launching", "expansion into", "opens new facility"]:
                    topics.add("Expansion")
                elif span in ["capital expenditure", "investing in infrastructure"]:
                    topics.add("Capital Expenditure")
                elif "ceo" in span or "cfo" in span or "president" in span or "leadership" in span:
                    topics.add("Leadership Change")
                else:
                    topics.add(span)

        # 3. Entity Extraction (NER)
        entities = {}
        for ent in nlp_doc.ents:
            if ent.label_ in ["ORG", "PERSON", "GPE", "MONEY", "PRODUCT"]:
                entities.setdefault(ent.label_, []).append(ent.text)
        
        # Deduplicate entity lists
        for label in entities:
            entities[label] = list(set(entities[label]))

        return NlpSignal(
            doc_id=doc.doc_id,
            sentiment=sentiment,
            key_topics=list(topics),
            risk_factors=list(risks),
            entities=entities
        )

    def match_trade_to_financials(self, shipping_records: List[ShippingRecord], 
                                  invoices: List[Invoice],
                                  name_threshold: int = 85,
                                  item_threshold: int = 70) -> List[TradeMatch]:
        """
        (UPDATED from core)
        Matches shipping records to invoices using fuzzy string matching for names
        and item descriptions.
        """
        matches = []
        
        for ship_record in shipping_records:
            best_match = None
            highest_score = 0
            
            for invoice in invoices:
                # Must match on date
                if ship_record.date.date() != invoice.date.date():
                    continue

                # Fuzzy match company names
                name_score = fuzz.token_set_ratio(ship_record.company_name, invoice.receiver_name)
                
                if name_score >= name_threshold:
                    # Calculate item description similarity
                    item_score = fuzz.token_set_ratio(ship_record.item_description, invoice.item_description)
                    
                    # Store the best match based on combined scores
                    total_score = name_score + item_score
                    if total_score > highest_score:
                        highest_score = total_score
                        best_match = (invoice, name_score, item_score)

            if best_match:
                invoice, name_score, item_score = best_match
                value_diff = abs(ship_record.value - invoice.amount)
                
                if value_diff < 0.01 and item_score >= item_threshold:
                    matches.append(TradeMatch(
                        match_type="Full Match",
                        shipping_id=ship_record.record_id,
                        invoice_id=invoice.invoice_id,
                        details=f"Full match (Name: {name_score}%, Item: {item_score}%)"
                    ))
                elif value_diff < 0.01 and item_score < item_threshold:
                    matches.append(TradeMatch(
                        match_type="Partial Match",
                        shipping_id=ship_record.record_id,
                        invoice_id=invoice.invoice_id,
                        details=f"Item mismatch (Name: {name_score}%, Item: {item_score}%)"
                    ))
                else:
                    matches.append(TradeMatch(
                        match_type="Discrepancy",
                        shipping_id=ship_record.record_id,
                        invoice_id=invoice.invoice_id,
                        details=f"Value discrepancy (Name: {name_score}%, Item: {item_score}%)",
                        value_discrepancy=value_diff
                    ))
        
        return matches

    def detect_unusual_funding_activity(self, funding_data: List[FundingEvent], 
                                      z_score_threshold: float = 3.0) -> List[FundingAnomaly]:
        """
        (UPDATED from core)
        Identifies funding anomalies using statistical methods (Z-score)
        and velocity checks.
        """
        anomalies = []
        if not funding_data:
            return []

        amounts = np.array([event.amount for event in funding_data])
        
        # Calculate Z-scores for amounts
        if len(amounts) > 1:
            mean_amount = np.mean(amounts)
            std_dev_amount = np.std(amounts)
            
            # Avoid division by zero if all amounts are identical
            if std_dev_amount == 0:
                std_dev_amount = 1 
        else:
            mean_amount = amounts[0]
            std_dev_amount = 1

        backer_activity = {}
        project_velocity = {}

        for event in funding_data:
            # 1. Check for high-value anomalies using Z-score
            z_score = abs(event.amount - mean_amount) / std_dev_amount
            if z_score > z_score_threshold:
                anomalies.append(FundingAnomaly(
                    project_id=event.project_id,
                    backer_id=event.backer_id,
                    anomaly_type="High Value Investment (Statistically)",
                    description=f"Backer {event.backer_id} made investment of {event.amount}, "
                                f"which is {z_score:.2f} std devs from the mean.",
                    timestamp=event.date
                ))
            
            # 2. Track activity for velocity and backer analysis
            backer_activity.setdefault(event.backer_id, []).append(event)
            key = (event.project_id, event.date.strftime("%Y-%m-%d-%H"))
            project_velocity[key] = project_velocity.get(key, 0) + 1

        # 3. Analyze backer behavior (e.g., new influential backer)
        for backer_id, events in backer_activity.items():
            if len(events) == 1: # A backer's first appearance
                z_score = abs(events[0].amount - mean_amount) / std_dev_amount
                if z_score > z_score_threshold / 2: # Lower threshold for new backers
                     anomalies.append(FundingAnomaly(
                        project_id=events[0].project_id,
                        backer_id=backer_id,
                        anomaly_type="New Influential Backer",
                        description=f"New backer {backer_id} appeared with a large single investment ({events[0].amount}).",
                        timestamp=events[0].date
                    ))

        # 4. Analyze velocity
        # Calculate velocity threshold (e.g., 3 std devs above mean hourly velocity)
        velocities = np.array(list(project_velocity.values()))
        if len(velocities) > 1:
            mean_velocity = np.mean(velocities)
            std_velocity = np.std(velocities)
            velocity_threshold = mean_velocity + (3 * std_velocity)
        else:
            velocity_threshold = 5 # Default fallback

        for (project_id, hour_str), count in project_velocity.items():
            if count > velocity_threshold:
                anomalies.append(FundingAnomaly(
                    project_id=project_id,
                    backer_id="N/A",
                    anomaly_type="High Velocity",
                    description=f"Project {project_id} received {count} investments in a single hour ({hour_str}).",
                    timestamp=datetime.strptime(hour_str, "%Y-%m-%d-%H")
                ))

        return anomalies

    def correlate_payment_flows(self, transactions: List[Transaction], 
                                entity_mappings: Dict[str, str]) -> List[PaymentFlowCorrelation]:
        """
        (UPDATED from core)
        Cross-checks corporate accounts, crypto wallets, or shell entities
        using graph analysis with NetworkX.
        """
        
        G = nx.DiGraph()
        
        # Add nodes with their entity type as an attribute
        for tx in transactions:
            for acc in [tx.from_account, tx.to_account]:
                if acc not in G:
                    G.add_node(acc, type=entity_mappings.get(acc, "unknown"))
        
        # Add edges with transaction data
        for tx in transactions:
            G.add_edge(tx.from_account, tx.to_account, tx_id=tx.tx_id, amount=tx.amount)

        correlations = []
        corporate_nodes = [n for n, attr in G.nodes(data=True) if attr.get('type') == 'corporate']
        crypto_nodes = [n for n, attr in G.nodes(data=True) if attr.get('type') == 'crypto']
        
        # Find all simple paths from corporate accounts to crypto wallets
        for start_node in corporate_nodes:
            for end_node in crypto_nodes:
                # Use cutoff to prevent runaway searches in dense graphs
                paths_generator = nx.all_simple_paths(G, source=start_node, target=end_node, cutoff=10)
                
                for path in paths_generator:
                    # Check if the path goes through a shell company
                    path_types = [G.nodes[n]['type'] for n in path]
                    
                    # Check if any intermediary (not start/end) is a shell
                    if "shell" in path_types[1:-1]:
                        
                        # Calculate total amount (this is simplified; just sums first edge)
                        first_edge_data = G.get_edge_data(path[0], path[1])
                        total_amount = first_edge_data.get('amount', 0)

                        correlations.append(PaymentFlowCorrelation(
                            flow_id=f"flow_{start_node}_{end_node}",
                            start_entity=start_node,
                            end_entity=end_node,
                            intermediaries=[n for n in path[1:-1] if G.nodes[n]['type'] == 'shell'],
                            total_amount=total_amount,
                            path=path
                        ))
                            
        return correlations

# --- Typer App & Commands (Plugin-specific CLI) ---

app = typer.Typer(
    name="financials",
    help="Analyze financial documents, trade, funding, and payment flows.",
    no_args_is_help=True
)

# --- Helper Functions for Commands ---

def load_json_data(path: Path) -> List[dict]:
    """Loads a list of objects from a JSON file."""
    if not path.exists():
        print(f"Error: File not found at {path}")
        raise typer.Exit(code=1)
    with open(path, 'r') as f:
        try:
            data = json.load(f)
            if not isinstance(data, list):
                print(f"Error: JSON file {path} must contain a list of objects.")
                raise typer.Exit(code=1)
            return data
        except json.JSONDecodeError:
            print(f"Error: Could not decode JSON from {path}")
            raise typer.Exit(code=1)

def parse_date(date_str: str) -> datetime:
    """Helper to parse ISO-ish date strings."""
    return datetime.fromisoformat(date_str)


# --- Typer Commands ---

@app.command("analyze-docs")
def analyze_documents(
    docs_file: Path = typer.Option(
        ..., "--file", "-f",
        help="Path to a JSON file containing a list of financial documents.",
        exists=True, readable=True,
    )
):
    """Extract NLP signals from unstructured financial documents (SEC filings, etc)."""
    console = Console()
    analyzer = FinancialMarketSignalAnalyzer()

    if analyzer.nlp is None:
        console.print("[bold red]Error: spaCy model not loaded.[/bold red]")
        console.print("Run: [yellow]python -m spacy download en_core_web_sm[/yellow]")
        raise typer.Exit(code=1)

    console.print(f"Loading documents from [cyan]{docs_file}[/cyan]...")
    doc_data = load_json_data(docs_file)
    documents = [
        FinancialDocument(
            doc_id=d.get('doc_id', f'doc_{i}'), 
            source_url=d.get('source_url', d.get('source', 'Unknown')), # Allow for both keys
            timestamp=parse_date(d.get('timestamp', d.get('date'))), # Allow for both keys
            content=d.get('content', '')
        ) for i, d in enumerate(doc_data) if d.get('content')
    ]

    console.print(f"Analyzing {len(documents)} documents...")
    table = Table(title="NLP Signal Analysis")
    table.add_column("Doc ID", style="cyan")
    table.add_column("Sentiment", style="magenta")
    table.add_column("Topics", style="green")
    table.add_column("Risk Factors", style="red")
    table.add_column("Entities (ORG)", style="yellow")

    for doc in documents:
        signal = analyzer.extract_signals_from_document(doc)
        orgs = ", ".join(signal.entities.get("ORG", []))
        table.add_row(signal.doc_id, signal.sentiment, ", ".join(signal.key_topics), ", ".join(signal.risk_factors), orgs)
    
    console.print(table)

@app.command("match-trades")
def match_trades(
    shipping_file: Path = typer.Option(..., "--shipping", help="Path to a JSON file of shipping records.", exists=True, readable=True),
    invoice_file: Path = typer.Option(..., "--invoices", help="Path to a JSON file of invoices.", exists=True, readable=True)
):
    """Match shipping & logistics records against financial invoices."""
    console = Console()
    analyzer = FinancialMarketSignalAnalyzer()

    shipping_data = load_json_data(shipping_file)
    shipping_records = [
        ShippingRecord(**d, date=parse_date(d.get('date'))) for d in shipping_data
    ]
    
    invoice_data = load_json_data(invoice_file)
    invoices = [
        Invoice(**d, date=parse_date(d.get('date'))) for d in invoice_data
    ]

    console.print(f"Matching {len(shipping_records)} shipping records against {len(invoices)} invoices...")
    matches = analyzer.match_trade_to_financials(shipping_records, invoices)

    table = Table(title="Trade & Logistics Match Results")
    table.add_column("Match Type", style="cyan")
    table.add_column("Shipping ID", style="magenta")
    table.add_column("Invoice ID", style="green")
    table.add_column("Value Discrepancy", style="red")
    table.add_column("Details", style="yellow")
    
    for match in matches:
        color = "green"
        if match.match_type == "Discrepancy": color = "red"
        elif match.match_type == "Partial Match": color = "yellow"
        discrepancy_str = f"${match.value_discrepancy:,.2f}" if match.value_discrepancy else "N/A"
        table.add_row(f"[{color}]{match.match_type}[/{color}]", match.shipping_id, match.invoice_id, discrepancy_str, match.details)
    
    console.print(table)

@app.command("find-funding-anomalies")
def find_funding_anomalies(
    funding_file: Path = typer.Option(..., "--file", "-f", help="Path to a JSON file of funding events.", exists=True, readable=True),
    z_score: float = typer.Option(3.0, "--z-score", help="Z-score threshold for statistical anomalies.")
):
    """Identify emerging backers or unusual funding activity."""
    console = Console()
    analyzer = FinancialMarketSignalAnalyzer()

    event_data = load_json_data(funding_file)
    funding_events = [
        FundingEvent(**d, date=parse_date(d.get('date'))) for d in event_data
    ]

    console.print(f"Analyzing {len(funding_events)} funding events with Z-Score threshold of {z_score}...")
    anomalies = analyzer.detect_unusual_funding_activity(funding_events, z_score_threshold=z_score)

    table = Table(title="Funding Anomaly Detection")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Project ID", style="magenta")
    table.add_column("Backer ID", "N/A", style="green")
    table.add_column("Anomaly Type", style="red")
    table.add_column("Description", style="yellow")
    
    for anomaly in anomalies:
        table.add_row(str(anomaly.timestamp), anomaly.project_id, anomaly.backer_id, anomaly.anomaly_type, anomaly.description)
    
    console.print(table)

@app.command("correlate-flows")
def correlate_flows(
    tx_file: Path = typer.Option(..., "--transactions", help="Path to a JSON file of transactions.", exists=True, readable=True),
    map_file: Path = typer.Option(..., "--entity-map", help="Path to a JSON file mapping account IDs to entity types.", exists=True, readable=True)
):
    """Cross-check corporate accounts, crypto wallets, or shell entities."""
    console = Console()
    analyzer = FinancialMarketSignalAnalyzer()

    tx_data = load_json_data(tx_file)
    transactions = [
        Transaction(**d, date=parse_date(d.get('date'))) for d in tx_data
    ]

    with open(map_file, 'r') as f:
        entity_mappings = json.load(f)
    
    console.print(f"Analyzing {len(transactions)} transactions with {len(entity_mappings)} entity mappings...")
    correlations = analyzer.correlate_payment_flows(transactions, entity_mappings)
    
    table = Table(title="Payment Flow Correlation")
    table.add_column("Start Entity", style="cyan")
    table.add_column("End Entity", style="magenta")
    table.add_column("Intermediaries (Shells)", style="red")
    table.add_column("Total Amount", style="green")
    table.add_column("Full Path", style="yellow")

    for flow in correlations:
        table.add_row(flow.start_entity, flow.end_entity, ", ".join(flow.intermediaries), f"${flow.total_amount:,.2f}", " -> ".join(flow.path))
    
    console.print(table)

if __name__ == "__main__":
    app()