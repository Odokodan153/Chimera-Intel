# src/chimera_intel/core/mlint_linking.py

import logging
import asyncio
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from neo4j import Driver
from datetime import datetime, date, timedelta
from thefuzz import fuzz
from abc import ABC, abstractmethod
from sqlmodel import Field as SQLField, Session, SQLModel, select

# Assuming existing imports from other modules in the project
# These imports are based on the file structure and previous context
from .mlint_graph import get_neo4j_driver, link_wallet_to_person, link_company_to_ubo
from .corporate_records import get_ubo_data, CompanyDetails
from .mlint_analysis import check_crypto_wallet, analyze_entity_risk, WalletRiskProfile, EntityRiskProfile
from .database import get_db_session, engine # Import real DB components

logger = logging.getLogger(__name__)

# --- EXISTING MODELS (EntityResolutionResult, etc. - assumed) ---

class EntityResolutionResult(BaseModel):
    """
    A placeholder for the result of a global entity resolution.
    This would contain all linked entities (wallets, companies, people)
    and their risk profiles.
    """
    entity_id: str
    status: str
    risk_profile: Optional[EntityRiskProfile] = None
    linked_entities: List[Dict[str, Any]] = Field(default_factory=list)


# --- NEW: Trade-to-Payment Correlation Models (Database-backed) ---

class TradeRecord(SQLModel, table=True):
    """
    Database model for a trade record (e.g., from a Bill of Lading).
    """
    id: Optional[int] = SQLField(default=None, primary_key=True)
    record_id: str = SQLField(index=True, unique=True, description="Bill of Lading or unique trade ID")
    exporter_name: str = SQLField(index=True)
    importer_name: str = SQLField(index=True)
    amount: float
    currency: str
    ship_date: date
    description_of_goods: str

class PaymentRecord(SQLModel, table=True):
    """
    Database model for a financial payment record (e.g., SWIFT, TT).
    """
    id: Optional[int] = SQLField(default=None, primary_key=True)
    record_id: str = SQLField(index=True, unique=True, description="SWIFT, wire, or unique transaction ID")
    sender_name: str = SQLField(index=True)
    receiver_name: str = SQLField(index=True)
    amount: float
    currency: str
    payment_date: date
    origin_bank_country: str = SQLField(max_length=3)

class TradeCorrelationResult(BaseModel):
    """
    Pydantic model for the result of a trade/payment correlation check.
    """
    trade_id: str
    payment_id: str
    is_match: bool = False
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    mismatch_reasons: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)

# --- NEW: Abstract Data Source Interfaces ---

class TradeDataSource(ABC):
    """Abstract base class for a trade data source."""
    @abstractmethod
    async def get_trade_by_record_id(self, record_id: str) -> Optional[TradeRecord]:
        """Fetches a trade record by its unique ID."""
        pass

class PaymentDataSource(ABC):
    """Abstract base class for a payment data source."""
    @abstractmethod
    async def get_payment_by_record_id(self, record_id: str) -> Optional[PaymentRecord]:
        """Fetches a payment record by its unique ID."""
        pass

# --- NEW: Concrete "Real" Database Data Sources ---

class DatabaseTradeDataSource(TradeDataSource):
    """Real implementation for fetching trade data from the SQL database."""
    def __init__(self, session: Session):
        self.session = session

    async def get_trade_by_record_id(self, record_id: str) -> Optional[TradeRecord]:
        """
        Fetches a trade record from the database.
        
        Note: This is 'async' to match the interface, allowing for future
        async database drivers (like asyncpg) without changing the caller.
        The current `sqlmodel` session execution is synchronous.
        """
        try:
            statement = select(TradeRecord).where(TradeRecord.record_id == record_id)
            # The .first() call is synchronous
            result = self.session.exec(statement).first()
            return result
        except Exception as e:
            logger.error(f"Error fetching trade record {record_id} from DB: {e}", exc_info=True)
            return None

class DatabasePaymentDataSource(PaymentDataSource):
    """Real implementation for fetching payment data from the SQL database."""
    def __init__(self, session: Session):
        self.session = session

    async def get_payment_by_record_id(self, record_id: str) -> Optional[PaymentRecord]:
        """
        Fetches a payment record from the database.
        (See async note in DatabaseTradeDataSource)
        """
        try:
            statement = select(PaymentRecord).where(PaymentRecord.record_id == record_id)
            # The .first() call is synchronous
            result = self.session.exec(statement).first()
            return result
        except Exception as e:
            logger.error(f"Error fetching payment record {record_id} from DB: {e}", exc_info=True)
            return None

# --- NEW: Helper to create tables ---

def create_trade_payment_tables():
    """
    Ensures the TradeRecord and PaymentRecord tables are created in the
    database specified by the global `engine`.
    """
    try:
        SQLModel.metadata.create_all(engine)
        logger.info("TradeRecord and PaymentRecord tables checked/created.")
    except Exception as e:
        logger.error(f"Could not create trade/payment tables: {e}", exc_info=True)
        raise

# --- CORE: Trade-to-Payment Correlation Logic (Refactored) ---

async def correlate_trade_and_payment(
    trade_id: str, 
    payment_id: str,
    trade_db: TradeDataSource,
    payment_db: PaymentDataSource,
    amount_tolerance: float = 0.02, # 2%
    date_proximity_days: int = 30,
    name_match_threshold: int = 85 # 85/100
) -> TradeCorrelationResult:
    """
    Correlates a trade (Bill of Lading) with a payment (SWIFT/TT)
    using data from the provided data sources, fuzzy matching, and
    tolerance checks.
    """
    
    # 1. Fetch data in parallel using the abstract data sources
    try:
        trade_record, payment_record = await asyncio.gather(
            trade_db.get_trade_by_record_id(trade_id),
            payment_db.get_payment_by_record_id(payment_id)
        )
    except Exception as e:
        logger.error(f"Error fetching trade/payment data: {e}", exc_info=True)
        return TradeCorrelationResult(
            trade_id=trade_id,
            payment_id=payment_id,
            confidence_score=0.0,
            mismatch_reasons=[f"Data fetching error: {e}"]
        )

    # 2. Handle missing records
    if not trade_record or not payment_record:
        reasons = []
        if not trade_record: reasons.append(f"Trade record {trade_id} not found.")
        if not payment_record: reasons.append(f"Payment record {payment_id} not found.")
        return TradeCorrelationResult(
            trade_id=trade_id,
            payment_id=payment_id,
            confidence_score=0.0,
            mismatch_reasons=reasons
        )

    logger.info(f"Correlating {trade_id} (Exporter: {trade_record.exporter_name}) with {payment_id} (Sender: {payment_record.sender_name})")

    mismatch_reasons = []
    confidence_factors = {}

    # 3. Check Currency (Hard check)
    if trade_record.currency.upper() != payment_record.currency.upper():
        mismatch = f"Currency mismatch: Trade={trade_record.currency}, Payment={payment_record.currency}"
        return TradeCorrelationResult(
            trade_id=trade_id,
            payment_id=payment_id,
            confidence_score=0.0,
            mismatch_reasons=[mismatch],
            evidence={"trade_currency": trade_record.currency, "payment_currency": payment_record.currency}
        )

    # 4. Check Amount (Tolerance)
    amount_diff = abs(trade_record.amount - payment_record.amount)
    amount_diff_percent = amount_diff / trade_record.amount if trade_record.amount > 0 else 0
    if amount_diff_percent > amount_tolerance:
        mismatch_reasons.append(f"Amount mismatch: {amount_diff_percent:.2%} difference (Tolerance: {amount_tolerance:.2%})")
        confidence_factors["amount"] = 0.5 # Apply penalty
    else:
        confidence_factors["amount"] = 1.0

    # 5. Check Date (Proximity)
    date_diff = abs(trade_record.ship_date - payment_record.payment_date)
    if date_diff.days > date_proximity_days:
        mismatch_reasons.append(f"Date proximity mismatch: {date_diff.days} days apart (Tolerance: {date_proximity_days} days)")
        confidence_factors["date"] = 0.7 # Apply penalty
    else:
        confidence_factors["date"] = 1.0

    # 6. Check Parties (Fuzzy Match)
    # Using token_set_ratio is robust to extra words (e.g., "Ltd", "Inc")
    exporter_sender_score = fuzz.token_set_ratio(trade_record.exporter_name, payment_record.sender_name)
    importer_receiver_score = fuzz.token_set_ratio(trade_record.importer_name, payment_record.receiver_name)

    if exporter_sender_score < name_match_threshold:
        mismatch_reasons.append(f"Exporter/Sender name mismatch: Score {exporter_sender_score} < {name_match_threshold}")
        confidence_factors["exporter"] = exporter_sender_score / 100.0 # Proportional confidence
    else:
        confidence_factors["exporter"] = 1.0
        
    if importer_receiver_score < name_match_threshold:
        mismatch_reasons.append(f"Importer/Receiver name mismatch: Score {importer_receiver_score} < {name_match_threshold}")
        confidence_factors["importer"] = importer_receiver_score / 100.0 # Proportional confidence
    else:
        confidence_factors["importer"] = 1.0

    # 7. Calculate final score (simple product of factors)
    final_score = (
        confidence_factors["amount"] *
        confidence_factors["date"] *
        confidence_factors["exporter"] *
        confidence_factors["importer"]
    )
    
    # A final hard threshold to declare a "match"
    is_match = final_score > 0.8 

    return TradeCorrelationResult(
        trade_id=trade_id,
        payment_id=payment_id,
        is_match=is_match,
        confidence_score=final_score,
        mismatch_reasons=mismatch_reasons,
        evidence={
            "amount_diff_percent": amount_diff_percent,
            "date_diff_days": date_diff.days,
            "exporter_sender_score": exporter_sender_score,
            "importer_receiver_score": importer_receiver_score,
            "factors": confidence_factors
        }
    )

async def run_trade_correlation_from_db(trade_id: str, payment_id: str) -> TradeCorrelationResult:
    """
    Async entry point for the plugin/CLI.
    This function handles getting a DB session and initializing the
    "real" data sources before calling the core logic.
    """
    try:
        # Use the shared DB session factory
        with get_db_session() as session:
            trade_db = DatabaseTradeDataSource(session)
            payment_db = DatabasePaymentDataSource(session)
            
            # Await the core logic
            return await correlate_trade_and_payment(trade_id, payment_id, trade_db, payment_db)
            
    except Exception as e:
        logger.error(f"Failed to run DB-backed trade correlation: {e}", exc_info=True)
        return TradeCorrelationResult(
            trade_id=trade_id,
            payment_id=payment_id,
            confidence_score=0.0,
            mismatch_reasons=[f"Database connection error: {e}"]
        )


# --- EXISTING FUNCTIONS (Entity Resolution - assumed) ---

async def resolve_entity_globally(entity_id: str, entity_type: str = "auto") -> EntityResolutionResult:
    """
    Resolves an entity across all financial crime data sources.
    
    This function would:
    1. Identify the entity type (if 'auto').
    2. Fetch data from internal DBs (SQL, Neo4j).
    3. Enrich via external APIs (Corporate Records, Chainalysis, etc.).
    4. Link all found entities in the Neo4j graph.
    5. Return a consolidated risk profile.
    
    (This is a conceptual implementation based on your prompt)
    """
    logger.info(f"Globally resolving entity: {entity_id} (Type: {entity_type})")
    
    driver: Optional[Driver] = None
    try:
        driver = get_neo4j_driver()
    except Exception as e:
        logger.error(f"Failed to get Neo4j driver: {e}")
        return EntityResolutionResult(entity_id=entity_id, status="Error: DB connection failed")

    # --- This is where the multi-dataset fusion would happen ---
    # 1. Fetch UBO data (Corporate Records)
    # 2. Fetch Wallet risk (Blockchain Analytics)
    # 3. Fetch Company risk (Jurisdiction, Shell status)
    # 4. Use `link_...` functions to write to Neo4j
    # 5. Run graph queries to find 2nd/3rd degree links
    
    # (Example stub)
    tasks = []
    if entity_type in ["company", "auto"]:
        tasks.append(get_ubo_data(entity_id)) # from corporate_records
    if entity_type in ["wallet", "auto"]:
        tasks.append(check_crypto_wallet(entity_id)) # from mlint_analysis
    
    # Run enrichment tasks concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    risk_profile = None
    linked_entities_list = []

    # Process results... link to graph...
    for res in results:
        if isinstance(res, CompanyDetails) and driver:
            # Logic to link company and UBOs in Neo4j
            link_company_to_ubo(driver, res.company_id, res.ubos)
            linked_entities_list.extend([ubo.name for ubo in res.ubos])
        elif isinstance(res, WalletRiskProfile) and driver:
            # Logic to link wallet to person (if possible)
            # link_wallet_to_person(driver, res.wallet_address, person_id)
            pass
        elif isinstance(res, Exception):
            logger.warning(f"Error during entity resolution task: {res}")

    
    # Finally, get the consolidated profile from the graph
    if driver:
        try:
            risk_profile = await analyze_entity_risk(driver, entity_id, entity_type)
        except Exception as e:
            logger.error(f"Failed to analyze entity risk in graph: {e}", exc_info=True)
        finally:
            driver.close()

    logger.info(f"Resolution for {entity_id} complete.")
    
    # Return placeholder result
    return EntityResolutionResult(
        entity_id=entity_id,
        status="Completed",
        risk_profile=risk_profile,
        linked_entities=[{"id": e, "type": "person"} for e in linked_entities_list]
    )