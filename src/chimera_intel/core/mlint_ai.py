"""
MLint AI Module
Handles NLP summarization, ML model training, explainability (SHAP),
and advanced Graph ML (GNNs).
(Updated with a REAL NLP classifier, REAL summarizer, and SWIFT NLP)
"""

import logging
import pandas as pd
import numpy as np
import shap
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier
from typing import List, Dict, Any, Optional
import asyncio

from .schemas import AdverseMediaHit, ExplainabilityResult, GnnAnomalyResult, Transaction
from .mlint_graph import GraphAnalyzer 

# --- New: Real NLP Imports ---
try:
    from transformers import pipeline
except ImportError:
    print("WARNING: 'transformers' library not found. NLP classification will be disabled.")
    pipeline = None

# Configure logging
log = logging.getLogger(__name__)

# --- NLP / Adverse Media AI (Req: AI Value) ---

# --- Cache for NLP Pipelines ---
_nlp_classifier = None
_nlp_summarizer = None
_swift_classifier = None # <-- Task 5

def get_nlp_classifier():
    """Initializes and caches the NLP zero-shot pipeline."""
    global _nlp_classifier
    if _nlp_classifier is None:
        if pipeline is None:
            log.warning("Transformers library not available. Cannot initialize NLP classifier.")
            return None
        try:
            log.info("Loading NLP zero-shot classification model (facebook/bart-large-mnli)...")
            _nlp_classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
            log.info("NLP classification model loaded successfully.")
        except Exception as e:
            log.error(f"Failed to load NLP classification model: {e}", exc_info=True)
            return None
    return _nlp_classifier

def get_nlp_summarizer():
    """Initializes and caches the NLP summarization pipeline."""
    global _nlp_summarizer
    if _nlp_summarizer is None:
        if pipeline is None:
            log.warning("Transformers library not available. Cannot initialize NLP summarizer.")
            return None
        try:
            log.info("Loading NLP summarization model (sshleifer/distilbart-cnn-12-6)...")
            _nlp_summarizer = pipeline("summarization", model="sshleifer/distilbart-cnn-12-6")
            log.info("NLP summarization model loaded successfully.")
        except Exception as e:
            log.error(f"Failed to load NLP summarization model: {e}", exc_info=True)
            return None
    return _nlp_summarizer

# --- REAL Summarization Implementation ---
async def summarize_adverse_media_ai(articles: List[AdverseMediaHit]) -> str:
    """
    Uses a real transformer model to summarize adverse media hits.
    """
    if not articles:
        return "No adverse media found."

    summarizer = get_nlp_summarizer()
    if summarizer is None:
        return "Summarization model not available."

    text_to_summarize = " ".join([a.headline + ": " + a.snippet for a in articles if a.snippet])
    if not text_to_summarize:
        return "No article content available for summarization."
        
    max_length = 1024
    if len(text_to_summarize) > max_length:
        text_to_summarize = text_to_summarize[:max_length]

    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            None,
            lambda: summarizer(text_to_summarize, max_length=150, min_length=30, do_sample=False)
        )
        return result[0]['summary_text']
    except Exception as e:
        log.error(f"Error during NLP summarization: {e}")
        return "Failed to generate AI summary."

# --- REAL Classification Implementation ---
RISK_CATEGORIES = [
    "Fraud", 
    "Money Laundering", 
    "Sanctions", 
    "Bribery & Corruption", 
    "Regulatory Investigation",
    "Terrorist Financing",
    "Cybercrime"
]

async def classify_adverse_media_ai(text: str) -> List[str]:
    """
    Uses a real zero-shot classification model to categorize text.
    """
    classifier = get_nlp_classifier()
    if classifier is None:
        return ["Unclassified"]

    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            None, 
            lambda: classifier(text, candidate_labels=RISK_CATEGORIES, multi_label=True)
        )
    except Exception as e:
        log.error(f"Error during NLP classification: {e}")
        return ["Unclassified"]

    confidence_threshold = 0.70 # 70% confidence
    
    classified_categories = []
    for i, label in enumerate(result['labels']):
        if result['scores'][i] > confidence_threshold:
            classified_categories.append(label)
            
    if not classified_categories:
        return ["Unclassified"]
        
    return classified_categories

# --- New: Task 5 - Advanced SWIFT Enrichment ---

SWIFT_RISK_CATEGORIES = [
    "Vague Payment Description",
    "Sanctions Evasion Language",
    "Structuring Language",
    "High Risk Goods",
]

def get_swift_classifier():
    """Initializes and caches the NLP zero-shot pipeline for SWIFT."""
    global _swift_classifier
    if _swift_classifier is None:
        if pipeline is None:
            log.warning("Transformers library not available. Cannot initialize SWIFT classifier.")
            return None
        try:
            log.info("Loading NLP zero-shot classification model for SWIFT...")
            _swift_classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
            log.info("SWIFT NLP model loaded successfully.")
        except Exception as e:
            log.error(f"Failed to load SWIFT NLP model: {e}", exc_info=True)
            return None
    return _swift_classifier

async def analyze_swift_text_ai(text: str) -> List[str]:
    """
    Uses a real zero-shot classification model to categorize SWIFT text.
    """
    classifier = get_swift_classifier()
    if classifier is None:
        return []

    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            None, 
            lambda: classifier(text, candidate_labels=SWIFT_RISK_CATEGORIES, multi_label=True)
        )
    except Exception as e:
        log.error(f"Error during SWIFT NLP classification: {e}")
        return []

    confidence_threshold = 0.60
    
    classified_categories = []
    for i, label in enumerate(result['labels']):
        if result['scores'][i] > confidence_threshold:
            classified_categories.append(label)
            
    return classified_categories
# --- End Task 5 ---


# --- Anomaly Detection (Unsupervised) ---

def train_isolation_forest(features: pd.DataFrame) -> IsolationForest:
    """Trains an IsolationForest model (Req B2)."""
    log.info(f"Training IsolationForest on {len(features)} samples...")
    model = IsolationForest(contamination='auto', random_state=42)
    model.fit(features)
    log.info("IsolationForest training complete.")
    return model

def score_with_isolation_forest(model: IsolationForest, features: pd.DataFrame) -> np.ndarray:
    """Scores new data. Returns anomaly scores."""
    scores = model.decision_function(features)
    scaled_scores = (scores.max() - scores) / (scores.max() - scores.min())
    return scaled_scores

# --- Risk Scoring (Supervised) (Req B2) ---

def train_supervised_model(labeled_data: pd.DataFrame) -> XGBClassifier:
    """
    Trains a supervised model (e.g., XGBoost) on labeled data
    from the 'human-in-the-loop' feedback (Req B2).
    """
    log.info(f"Training supervised XGBoost model on {len(labeled_data)} labeled samples...")
    if 'is_true_positive' not in labeled_data.columns:
        log.error("Missing 'is_true_positive' column for supervised training.")
        return None
        
    X = labeled_data.drop(columns=['is_true_positive'])
    y = labeled_data['is_true_positive']
    
    model = XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
    model.fit(X, y)
    log.info("XGBoost training complete.")
    return model

def predict_supervised_risk(model: XGBClassifier, features: pd.DataFrame) -> np.ndarray:
    """Predicts risk score (0.0 - 1.0) using the supervised model."""
    if model is None:
        return np.zeros(len(features))
    return model.predict_proba(features)[:, 1] # Probability of class 1 (risky)

# --- Explainability (SHAP) (Req B3, E5) ---

def get_model_explanation(
    model: Any, 
    features: pd.DataFrame, 
    model_type: str = 'xgboost'
) -> Optional[ExplainabilityResult]:
    """
    Generates SHAP-based explainability for a model prediction.
    """
    log.info(f"Generating SHAP explanation for {model_type} model...")
    try:
        if model_type == 'xgboost':
            explainer = shap.TreeExplainer(model)
        elif model_type == 'isoforest':
            explainer = shap.KernelExplainer(model.decision_function, shap.sample(features, 50))
        else:
            log.warning(f"SHAP explainer not implemented for model type: {model_type}")
            return None

        shap_values = explainer.shap_values(features.iloc[0:1])
        
        feature_names = features.columns
        if isinstance(shap_values, list): 
            shap_values = shap_values[1] 
            
        shap_dict = dict(zip(feature_names, shap_values[0]))
        
        top_features = sorted(shap_dict.items(), key=lambda item: abs(item[1]), reverse=True)[:5]
        top_features_dict = {f[0]: f[1] for f in top_features}

        summary = f"Risk score driven by: " + ", ".join([
            f"{f} ({'high' if v > 0 else 'low'})" for f, v in top_features
        ])

        return ExplainabilityResult(
            top_contributing_features=top_features_dict,
            human_readable_summary=summary
        )
    except Exception as e:
        log.error(f"Failed to generate SHAP explanation: {e}")
        return None

# --- Advanced Models (GNN) (Req B4) ---
# --- REAL Graph Anomaly Implementation ---
async def run_gnn_anomaly_detection() -> List[GnnAnomalyResult]:
    """
    Runs a graph-based anomaly detection algorithm (PageRank)
    to find structurally important nodes.
    """
    log.info("Running GNN/Graph anomaly detection...")
    graph_analyzer = None
    try:
        graph_analyzer = GraphAnalyzer()
        results = await graph_analyzer.run_pagerank_anomaly()
        return results
    except Exception as e:
        log.error(f"Failed to run GNN anomaly detection: {e}", exc_info=True)
        return []
    finally:
        if graph_analyzer:
            await graph_analyzer.close()


# --- Model Ops (Req C3) ---

def check_model_drift(
    new_features: pd.DataFrame, 
    baseline_features: pd.DataFrame
) -> Dict[str, Any]:
    """
    Monitors for model/data drift (Req C3).
    """
    from scipy.stats import ks_2samp
    drift_report = {}
    
    for col in baseline_features.columns:
        if col in new_features.columns:
            stat, p_value = ks_2samp(baseline_features[col], new_features[col])
            if p_value < 0.05: 
                drift_report[col] = {"drift_detected": True, "p_value": p_value}
    
    if drift_report:
        log.warning(f"Model drift detected in features: {list(drift_report.keys())}")
        
    return drift_report