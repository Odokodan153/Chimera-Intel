"""
This module provides advanced tools for detecting, extracting, and correlating
financial market signals using NLP, fuzzy matching, and graph analysis.
"""
import spacy
import networkx as nx
import numpy as np
from spacy.matcher import Matcher
from .schemas import (
    FinancialDocument,
    NlpSignal,
    ShippingRecord,
    Invoice,
    TradeMatch,
    FundingEvent,
    FundingAnomaly,
    Transaction,
    PaymentFlowCorrelation,
)
from typing import List, Dict
from datetime import datetime
from thefuzz import fuzz


class FinancialMarketSignalAnalyzer:
    """
    Analyzes financial documents, trade data, funding platforms, and payment flows
    using NLP, graph analysis, and statistical methods.
    """

    def __init__(self):
        try:
            self.nlp = spacy.load("en_core_web_sm")
            self.nlp.add_pipe("spacytextblob")
        except OSError:
            print(
                "Error: spaCy model 'en_core_web_sm' not found. "
                "Please run: python -m spacy download en_core_web_sm"
            )
            self.nlp = None
        
        self.matcher = Matcher(self.nlp.vocab)
        self.setup_matchers()
        print("FinancialMarketSignalAnalyzer initialized with real NLP and analysis tools.")

    def setup_matchers(self):
        """Set up spaCy Matcher patterns for topics and risks."""
        if not self.nlp:
            return
            
        # Risk patterns
        risk_patterns = [
            [{"LOWER": "regulatory"}, {"LOWER": "scrutiny"}],
            [{"LOWER": "litigation"}],
            [{"LOWER": "market"}, {"LOWER": "risk"}],
            [{"LOWER": "headwinds"}],
            [{"LOWER": "fraud"}]
        ]
        self.matcher.add("RISK_FACTORS", risk_patterns)

        # Topic patterns
        topic_patterns = [
            [{"LOWER": "merger"}],
            [{"LOWER": "acquisition"}],
            [{"LOWER": "new"}, {"LOWER": "market"}],
            [{"LOWER": "launching"}]
        ]
        self.matcher.add("KEY_TOPICS", topic_patterns)

    def extract_signals_from_document(self, doc: FinancialDocument) -> NlpSignal:
        """
        Uses spaCy for robust NLP (Sentiment, NER, Topic/Risk Matching).
        """
        if not self.nlp:
            return NlpSignal(doc.nlp_id, "neutral", [], [], {})

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
                if span in ["merger", "acquisition"]:
                    topics.add("M&A")
                elif span in ["new market", "launching"]:
                    topics.add("Expansion")
                else:
                    topics.add(span)

        # 3. Entity Extraction (NER)
        entities = {}
        for ent in nlp_doc.ents:
            if ent.label_ in ["ORG", "PERSON", "GPE", "MONEY"]:
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
        Matches shipping records to invoices using fuzzy string matching for names
        and item descriptions.
        """
        matches = []
        # This is O(n*m), which is acceptable for moderate lists.
        # For very large lists, a blocking/indexing strategy would be needed.
        
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
                paths = nx.all_simple_paths(G, source=start_node, target=end_node, cutoff=10) # Limit path length
                
                for path in paths:
                    # Check if the path goes through a shell company
                    path_types = [G.nodes[n]['type'] for n in path]
                    if "shell" in path_types[1:-1]: # Intermediary is a shell
                        
                        # Calculate total amount (this is simplified)
                        total_amount = 0
                        for i in range(len(path) - 1):
                            edge_data = G.get_edge_data(path[i], path[i+1])
                            total_amount += edge_data['amount']

                        correlations.append(PaymentFlowCorrelation(
                            flow_id=f"flow_{start_node}_{end_node}",
                            start_entity=start_node,
                            end_entity=end_node,
                            intermediaries=[n for n in path[1:-1] if G.nodes[n]['type'] == 'shell'],
                            total_amount=total_amount,
                            path=path
                        ))
                            
        return correlations