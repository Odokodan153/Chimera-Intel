"""
MLint Analysis
(Updated for Redis persistent history and Async SWIFT NLP)
"""

import pandas as pd
import logging
import re 
from typing import List, Dict, Any, Optional
import redis
import json
from .schemas import Transaction, SwiftMessage, TransactionAnalysisResult, SwiftAnalysisResult, RiskLevel
from .mlint_ai import (
    score_with_isolation_forest, 
    predict_supervised_risk, 
    get_model_explanation,
    analyze_swift_text_ai 
)
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier
from .mlint_config import settings 

# Configure logging
log = logging.getLogger(__name__)

# --- Task 2: Persistent Entity History (Redis) ---
try:
    redis_client = redis.Redis(
        host=settings.redis_host, 
        port=settings.redis_port, 
        db=settings.redis_db,
        decode_responses=True 
    )
    redis_client.ping()
    log.info(f"Connected to Redis at {settings.redis_host}:{settings.redis_port}")
except redis.exceptions.ConnectionError as e:
    log.critical(f"FATAL: Cannot connect to Redis at {settings.redis_host}. {e}")
    redis_client = None # App will fail if this is None

WINDOW_SIZE = 10 # Number of transactions for rolling features
HISTORY_MAX_LEN = 100 # Max transactions to keep in history

# --- Feature Engineering (Req B1) ---

def extract_transactional_features(
    tx: Transaction, 
    historical_txs: List[Transaction]
) -> Dict[str, Any]:
    """
    Expands feature set for ML models (Req B1).
    """
    if not historical_txs:
        # Not enough history, return default features
        return {
            "amount": tx.amount,
            "tx_velocity_24h": 1,
            "avg_amount_10_tx": tx.amount,
            "counterparty_diversity_10_tx": 1,
            "is_high_value": 1.0 if tx.amount > 10000 else 0.0,
            "is_night_tx": 1.0 if 0 <= tx.timestamp.hour <= 6 else 0.0,
            "known_mixer_interaction": tx.metadata.get("known_mixer_interaction", 0.0),
            "invoice_mismatch": tx.metadata.get("invoice_mismatch", 0.0),
        }

    df = pd.DataFrame([t.dict() for t in historical_txs])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp')

    tx_time = tx.timestamp
    tx_velocity_24h = len(df[df['timestamp'] >= (tx_time - pd.Timedelta(hours=24))]) + 1
    
    avg_amount_10_tx = df.tail(WINDOW_SIZE)['amount'].mean()
    
    counterparties = set(df.tail(WINDOW_SIZE)['to_entity'])
    counterparty_diversity_10_tx = len(counterparties)
    
    known_mixer_interaction = tx.metadata.get("known_mixer_interaction", 0.0)
    invoice_mismatch = tx.metadata.get("invoice_mismatch", 0.0)

    features = {
        "amount": tx.amount,
        "tx_velocity_24h": tx_velocity_24h,
        "avg_amount_10_tx": avg_amount_10_tx,
        "counterparty_diversity_10_tx": counterparty_diversity_10_tx,
        "is_high_value": 1.0 if tx.amount > 10000 else 0.0,
        "is_night_tx": 1.0 if 0 <= tx.timestamp.hour <= 6 else 0.0,
        "known_mixer_interaction": known_mixer_interaction,
        "invoice_mismatch": invoice_mismatch,
    }
    
    return features

# --- SWIFT Message Analysis (Task 5 Updated) ---

SWIFT_RISK_JURISDICTIONS = {'IR', 'KP', 'SY'} # ISO 2

# --- Task 5: New SwiftParser ---
class SwiftParser:
    """
    A simple regex-based parser for MT103 fields.
    This is a demonstration; a real parser would be more robust.
    """
    
    FIELD_RE = re.compile(r":([0-9]{2}[A-Z]?):(.+?)(?=\n:[0-9]{2}[A-Z]?:|\n-})", re.DOTALL)

    def parse_mt103(self, message_text: str) -> Dict[str, str]:
        fields = {tag: value.strip() for tag, value in self.FIELD_RE.findall(message_text)}
        
        # Extract key fields
        # Field 50K: Ordering Customer
        sender = fields.get("50K", "Unknown Sender").split('\n')[-1]
        # Field 59: Beneficiary Customer
        beneficiary = fields.get("59", "Unknown Beneficiary").split('\n')[-1]
        # Field 70: Remittance Information
        purpose = fields.get("70", "No Purpose Stated")
        
        return {
            "sender": sender,
            "beneficiary": beneficiary,
            "purpose": purpose
        }

swift_parser = SwiftParser()
# --- End Task 5 ---


async def analyze_swift_message(msg: SwiftMessage) -> SwiftAnalysisResult: # <-- Now async
    """
    Analyzes a parsed SWIFT message for AML red flags.
    (Updated with AI/NLP text analysis on parsed fields)
    """
    log.info(f"Analyzing SWIFT message: {msg.mt_type} from {msg.sender_bic}")
    red_flags = []
    score = 0.0

    # 1. Check jurisdictions
    sender_country = msg.sender_bic[4:6].upper()
    receiver_country = msg.receiver_bic[4:6].upper()
    
    if sender_country in SWIFT_RISK_JURISDICTIONS or receiver_country in SWIFT_RISK_JURISDICTIONS:
        red_flags.append("High-risk jurisdiction detected")
        score = max(score, 0.9)

    # 2. Check for high value
    if msg.amount > 500_000:
        red_flags.append("High-value transaction")
        score = max(score, 0.5)

    # --- Task 5: Parse fields and use NLP ---
    try:
        parsed_fields = swift_parser.parse_mt103(msg.raw_content)
        
        # Create a text blob for AI analysis
        ai_text = (
            f"Sender: {parsed_fields['sender']}. "
            f"Beneficiary: {parsed_fields['beneficiary']}. "
            f"Purpose: {parsed_fields['purpose']}"
        )

        ai_flags = await analyze_swift_text_ai(ai_text)
        if ai_flags:
            red_flags.extend(ai_flags)
            score = max(score, 0.7) # AI flags carry significant weight
            log.info(f"SWIFT AI detected risks: {ai_flags}")
    except Exception as e:
        log.error(f"SWIFT AI analysis failed: {e}")
    # --- End Task 5 ---
        
    # 4. Determine Risk Level
    if score >= 0.8:
        level = RiskLevel.CRITICAL
    elif score >= 0.5:
        level = RiskLevel.HIGH
    elif score >= 0.2:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    return SwiftAnalysisResult(
        risk_score=score,
        risk_level=level,
        red_flags=red_flags or ["No red flags detected"]
    )


# --- Core Transaction Analysis Orchestrator ---

# --- Task 2: Updated History Functions ---
def get_historical_data(entity_id: str) -> List[Transaction]:
    """Fetches historical data from Redis."""
    if not redis_client:
        log.warning("Redis client not available. Returning no history.")
        return []
    try:
        tx_json_list = redis_client.lrange(entity_id, 0, HISTORY_MAX_LEN - 1)
        return [Transaction(**json.loads(tx_json)) for tx_json in tx_json_list]
    except Exception as e:
        log.error(f"Failed to get historical data for {entity_id} from Redis: {e}")
        return []

def update_historical_data(tx: Transaction):
    """Updates historical data in Redis (capped list)."""
    if not redis_client:
        log.warning("Redis client not available. Skipping history update.")
        return
    try:
        pipe = redis_client.pipeline()
        pipe.lpush(tx.from_entity, tx.json())
        pipe.ltrim(tx.from_entity, 0, HISTORY_MAX_LEN - 1)
        pipe.execute()
    except Exception as e:
        log.error(f"Failed to update historical data for {tx.from_entity} in Redis: {e}")
# --- End Task 2 ---


async def analyze_transaction_risk(
    tx: Transaction,
    iso_forest_model: IsolationForest,
    supervised_model: Optional[XGBClassifier],
    feature_order: List[str]
) -> TransactionAnalysisResult:
    """
    Orchestrates the full analysis of a single transaction (Req E4, B2, B3).
    """
    log.info(f"Analyzing transaction: {tx.tx_id}")
    
    # 0. Update and get history (now from Redis)
    history = get_historical_data(tx.from_entity)
    update_historical_data(tx) 
    
    # 1. Feature Engineering (Req B1)
    features_dict = extract_transactional_features(tx, history)
    
    try:
        features_vector = [features_dict[col] for col in feature_order]
    except KeyError as e:
        log.error(f"Missing feature {e} during vector creation. Check feature_order.")
        return None 
        
    features_df = pd.DataFrame([features_vector], columns=feature_order)

    # 2. Get Unsupervised Score (IsolationForest)
    if not iso_forest_model:
        log.warning(f"No IsolationForest model for tx {tx.tx_id}. Unsupervised score is 0.")
        unsupervised_score = 0.0
    else:
        unsupervised_score = score_with_isolation_forest(iso_forest_model, features_df)[0]
    
    # 3. Get Supervised Score (XGBoost)
    supervised_score = predict_supervised_risk(supervised_model, features_df)[0]
    
    # 4. Hybrid Scoring
    if supervised_model:
        hybrid_score = (supervised_score * 0.7) + (unsupervised_score * 0.3)
    else:
        hybrid_score = unsupervised_score # Fallback to unsupervised
    
    # 5. Get Explainability
    explanation = None
    if hybrid_score > 0.5 and supervised_model: 
        explanation = get_model_explanation(
            supervised_model, 
            features_df, 
            model_type='xgboost'
        )

    # 6. Apply Thresholds
    if hybrid_score >= 0.8:
        level = RiskLevel.CRITICAL
    elif hybrid_score >= 0.5:
        level = RiskLevel.HIGH
    elif hybrid_score >= 0.2:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW
        
    return TransactionAnalysisResult(
        transaction=tx,
        risk_score=hybrid_score,
        risk_level=level,
        anomaly_score_unsupervised=unsupervised_score,
        risk_score_supervised=supervised_score,
        explainability=explanation,
        contributing_features=features_dict
    )

# --- Backtesting / Evaluation (Req C1, E4) ---

def run_backtest(
    labeled_dataset: pd.DataFrame,
    iso_forest_model: IsolationForest,
    supervised_model: XGBClassifier,
    feature_order: List[str]
) -> Dict[str, Any]:
    """
    Runs analysis in "backtest mode" to evaluate metrics (Req C1, E4).
    """
    log.info(f"Running backtest on {len(labeled_dataset)} samples...")
    from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
    
    X_test = labeled_dataset[feature_order]
    y_true = labeled_dataset['is_true_positive']
    
    unsupervised_scores = score_with_isolation_forest(iso_forest_model, X_test)
    supervised_scores = predict_supervised_risk(supervised_model, X_test)
    hybrid_scores = (supervised_scores * 0.7) + (unsupervised_scores * 0.3)
    
    threshold = 0.5
    y_pred = [1 if score >= threshold else 0 for score in hybrid_scores]
    
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)
    
    metrics = {
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "confusion_matrix": cm.tolist(), # [[TN, FP], [FN, TP]]
        "num_samples": len(labeled_dataset),
        "false_positive_rate": cm[0, 1] / (cm[0, 0] + cm[0, 1]) if (cm[0, 0] + cm[0, 1]) > 0 else 0
    }
    
    log.info(f"Backtest complete. Precision: {precision:.4f}, Recall: {recall:.4f}")
    return metrics