"""
MLint Schemas
Defines the core data models used across the application.
"""
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
import uuid

# --- Enums ---

class EntityType(str, Enum):
    PERSON = "Person"
    COMPANY = "Company"
    WALLET = "Wallet"

class RiskLevel(str, Enum):
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class AnalystStatus(str, Enum):
    PENDING_REVIEW = "Pending Review"
    IN_REVIEW = "In Review"
    ESCALATED = "Escalated"
    CLOSED_FALSE_POSITIVE = "Closed (False Positive)"
    CLOSED_TRUE_POSITIVE = "Closed (True Positive)"

# --- Core Data Models ---

class Entity(BaseModel):
    name: str
    entity_type: EntityType
    jurisdiction: Optional[str] = None
    addresses: List[str] = Field(default_factory=list)
    entity_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

class Transaction(BaseModel):
    tx_id: str
    from_entity: str # e.g., "acct:12345" or "wallet:0xabc"
    to_entity: str
    amount: float
    currency: str
    timestamp: datetime = Field(default_factory=datetime.now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SwiftMessage(BaseModel):
    mt_type: str
    sender_bic: str
    receiver_bic: str
    amount: float
    currency: str
    raw_content: str
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

# --- Intelligence Results ---

class SanctionHit(BaseModel):
    source_list: str
    entity_name: str
    match_score: float
    details: Dict[str, Any] = Field(default_factory=dict)

class PepHit(BaseModel):
    name: str
    position: str
    country: str
    source_url: str

class UboInfo(BaseModel):
    company_name: str
    ubo_name: str
    confidence_score: float
    source: str

class AdverseMediaHit(BaseModel):
    url: str
    headline: str
    source_name: str
    publish_date: Optional[datetime] = None
    snippet: str
    risk_categories: List[str] = Field(default_factory=list)

# --- Analysis & Alerting ---

class ExplainabilityResult(BaseModel):
    top_contributing_features: Dict[str, float]
    human_readable_summary: str

class TransactionAnalysisResult(BaseModel):
    transaction: Transaction
    risk_score: float
    risk_level: RiskLevel
    anomaly_score_unsupervised: float
    risk_score_supervised: float
    explainability: Optional[ExplainabilityResult] = None
    contributing_features: Dict[str, Any] = Field(default_factory=dict)

class SwiftAnalysisResult(BaseModel):
    risk_score: float
    risk_level: RiskLevel
    red_flags: List[str] = Field(default_factory=list)

class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: f"ALERT-{uuid.uuid4()}")
    timestamp: datetime = Field(default_factory=datetime.now)
    tx_id: Optional[str] = None
    risk_score: float
    risk_level: RiskLevel
    reason: str
    feature_snapshot: Dict[str, Any] = Field(default_factory=dict)
    analyst_status: AnalystStatus = AnalystStatus.PENDING_REVIEW
    tags: List[str] = Field(default_factory=list)

class GnnAnomalyResult(BaseModel):
    node_id: str
    node_type: str
    score: float
    reason: str