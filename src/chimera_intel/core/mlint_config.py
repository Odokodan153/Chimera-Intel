"""
MLint Central Configuration
Uses pydantic-settings to load all environment-dependent variables.
"""

from pydantic_settings import BaseSettings
import logging
from typing import List, Optional

log = logging.getLogger(__name__)

class Settings(BaseSettings):
    # --- Infrastructure ---
    kafka_broker: str = "localhost:9092"
    kafka_topic: str = "transactions"
    kafka_dlq_topic: str = "transactions_dlq" # <-- Task 4: For failed messages
    
    swift_amqp_url: str = "amqp://guest:guest@localhost:5672/"
    swift_queue: str = "swift_mt103"
    
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"
    
    redis_host: str = "localhost" # <-- Task 2: For persistent history
    redis_port: int = 6379       # <-- Task 2
    redis_db: int = 0

    # --- API Keys ---
    # (Task 8: A Vault/K8s injector would populate 
    # these env vars in production)
    news_api_key: Optional[str] = None
    refinitiv_api_key: Optional[str] = None
    open_corporates_api_key: Optional[str] = None
    chainalysis_api_key: Optional[str] = None
    
    # --- Security (Task 8) ---
    message_signature_secret: str = "default-secret-key-replace-me" # For HMAC verification

    # --- Model & Feature Config ---
    iso_forest_model_path: str = "iso_forest.joblib"
    supervised_model_path: str = "xgb_model.joblib"
    
    # This feature order is critical and must match training
    feature_order: List[str] = [
        "amount", "tx_velocity_24h", "avg_amount_10_tx", 
        "counterparty_diversity_10_tx", "is_high_value", "is_night_tx",
        "known_mixer_interaction", "invoice_mismatch"
    ]

    class Config:
        env_file = ".env" # Load variables from a .env file
        env_file_encoding = 'utf-8'

try:
    settings = Settings()
    log.info("Loaded settings from .env file or environment.")
except Exception as e:
    log.critical(f"Failed to load settings: {e}. Using defaults.")
    # Fallback to default settings if .env is missing or invalid
    settings = Settings()