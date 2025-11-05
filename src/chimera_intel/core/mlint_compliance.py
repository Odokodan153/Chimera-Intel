# src/chimera_intel/core/mlint_compliance.py

import logging
import hashlib
import os
import json
from datetime import datetime
from typing import List, Optional, Any
from .schemas import ReviewCase
from sqlmodel import Field, Session, SQLModel, create_engine, select

# Assuming 'mlint_analysis' and 'database' are siblings in 'core'
from .mlint_analysis import AMLAlert
from .database import get_db_session, engine 

logger = logging.getLogger(__name__)

# --- PII (Personally Identifiable Information) Manager ---

class PiiManager:
    """
    Handles masking of PII data using a one-way hash.
    
    This provides pseudonymization. The original PII is not stored
    or recoverable by this service, adhering to privacy-by-design.
    The "unmasking" would happen by joining this hash against a
    secure, access-controlled PII vault, which is outside this scope.
    """
    def __init__(self, salt: Optional[str] = None):
        # Use a strong, configured salt in a real environment
        self.salt = (salt or os.environ.get("PII_HASH_SALT", "default_insecure_salt")).encode('utf-8')
        if "default_insecure_salt" in self.salt.decode():
            logger.warning("Using default PII hash salt. Set PII_HASH_SALT env var.")

    def mask_pii(self, data: str) -> str:
        """Hashes a single string of PII data."""
        if not data:
            return ""
        return "sha256:" + hashlib.sha256(data.encode('utf-8') + self.salt).hexdigest()

    def mask_aml_alert(self, alert: AMLAlert) -> AMLAlert:
        """
        Returns a new AMLAlert with sensitive PII in evidence hashed.
        This is a non-exhaustive example.
        """
        masked_alert = alert.copy(deep=True)
        
        # Example: Mask sensitive fields if they exist in evidence
        if "entity_name" in masked_alert.evidence:
            masked_alert.evidence["entity_name"] = self.mask_pii(masked_alert.evidence["entity_name"])
        
        if "ubo_names" in masked_alert.evidence and isinstance(masked_alert.evidence["ubo_names"], list):
            masked_alert.evidence["ubo_names"] = [self.mask_pii(name) for name in masked_alert.evidence["ubo_names"]]
            
        if "entity_trail" in masked_alert.evidence:
            # Mask names within the entity trail
            new_trail = []
            for item in masked_alert.evidence["entity_trail"]:
                new_item = item.copy()
                if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], dict):
                    # Handle trail format: (['Label'], {'id': '..', 'name': '..'})
                    props = item[1].copy()
                    if "name" in props and props["name"]:
                        props["name"] = self.mask_pii(props["name"])
                    new_item = (item[0], props)
                new_trail.append(new_item)
            masked_alert.evidence["entity_trail"] = new_trail

        # Mask any PII in the main message (simple replacement)
        # This is complex in reality; here we just mask the entity_id
        masked_alert.message = f"Alert for entity {self.mask_pii(alert.entity_id)}: {alert.type}"
        
        return masked_alert

class ReviewService:
    """
    Service for managing the analyst review queue.
    Connects AML alerts to the database-backed case management system.
    """
    def __init__(self, session: Session):
        self.session = session
        self.pii_manager = PiiManager()

    def submit_alert_for_review(self, alert: AMLAlert) -> ReviewCase:
        """
        Submits a new AMLAlert to the review queue.
        
        This logic now includes FUSION/DEDUPLICATION.
        If an identical (type + entity) OPEN case exists,
        it fuses this alert into that case instead of creating a new one.
        """
        
        # 1. Check for an existing open case to fuse with
        try:
            statement = select(ReviewCase).where(
                ReviewCase.alert_type == alert.type,
                ReviewCase.entity_id == alert.entity_id,
                ReviewCase.status == "OPEN"
            )
            existing_case = self.session.exec(statement).first()
            
            if existing_case:
                logger.info(f"Fusing alert for {alert.entity_id} into existing case {existing_case.id}")
                
                existing_case.fusion_count += 1
                existing_case.updated_at = datetime.utcnow()
                
                # Add a system note for the fusion
                fusion_note = f"\n[SYSTEM @ {datetime.utcnow()}]: Fused new '{alert.type}' alert. Total count: {existing_case.fusion_count}."
                existing_case.notes = (existing_case.notes or "") + fusion_note
                
                self.session.add(existing_case)
                self.session.commit()
                self.session.refresh(existing_case)
                return existing_case

        except Exception as e:
            # If fusion check fails, log it but proceed to create a new case
            logger.error(f"Error checking for alert fusion: {e}", exc_info=True)
            self.session.rollback()

        # 2. No existing case found (or fusion failed) - Create a new case
        logger.info(f"Creating new review case for: {alert.type} on entity {alert.entity_id}")
        
        # 3. Mask PII in the alert
        masked_alert = self.pii_manager.mask_aml_alert(alert)
        
        # 4. Create the ReviewCase
        case = ReviewCase(
            alert_type=masked_alert.type,
            entity_id=alert.entity_id, # Store the *original* ID for joins
            status="OPEN",
            alert_json=masked_alert.json(),
            fusion_count=1 # This is the first alert
        )
        
        # 5. Add to session and commit
        try:
            self.session.add(case)
            self.session.commit()
            self.session.refresh(case)
            logger.info(f"Successfully created ReviewCase {case.id}")
            return case
        except Exception as e:
            logger.error(f"Failed to submit new alert to review queue: {e}")
            self.session.rollback()
            raise

    def get_case_by_id(self, case_id: int) -> Optional[ReviewCase]:
        """Fetches a single case by its primary ID."""
        return self.session.get(ReviewCase, case_id)

    def get_cases_by_status(self, status: str = "OPEN") -> List[ReviewCase]:
        """Gets all cases matching a given status."""
        statement = select(ReviewCase).where(ReviewCase.status == status)
        return self.session.exec(statement).all()

    def resolve_case(self, case_id: int, new_status: str, notes: str, assignee: str = "system") -> Optional[ReviewCase]:
        """
        Updates a case's status and adds review notes.
        This simulates an analyst action.
        """
        case = self.get_case_by_id(case_id)
        if not case:
            logger.warning(f"No case found with ID {case_id} to resolve.")
            return None
            
        case.status = new_status
        case.notes = (case.notes or "") + f"\n[{assignee} @ {datetime.utcnow()}]: {notes}"
        case.updated_at = datetime.utcnow()
        case.assignee = assignee
        
        try:
            self.session.add(case)
            self.session.commit()
            self.session.refresh(case)
            logger.info(f"Case {case_id} resolved. New status: {new_status}")
            return case
        except Exception as e:
            logger.error(f"Failed to resolve case {case_id}: {e}")
            self.session.rollback()
            raise

# Helper function to initialize the DB table
def create_review_db_and_tables():
    """Ensures the ReviewCase table is created in the database."""
    # Uses the global engine from .database
    SQLModel.metadata.create_all(engine)