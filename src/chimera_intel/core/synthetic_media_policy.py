"""
Synthetic Media Generation Policy Engine.

Implements pre-generation checks based on defined ethical policies,
risk thresholds, and approval workflows.
(Implements requirements from Point 9).
"""

import logging
from typing import List, Optional, Literal
from pydantic import BaseModel, Field

from .schemas import BaseSchema # Re-using BaseSchema

logger = logging.getLogger(__name__)

# --- Policy Definitions (Req 9) ---

# Configurable lists for blocked/sensitive subject categories
BLOCKED_SUBJECT_CATEGORIES = [
    "minor",
    "known_victim_of_crime",
    "sanctioned_person",
]

SENSITIVE_SUBJECT_CATEGORIES = [
    "public_official_sensitive", # e.g., judges, specific elected officials
]

# Allowed, low-risk categories
ALLOWED_SUBJECT_CATEGORIES = [
    "stock_synthetic_face", # Non-existent person
    "consenting_adult_corporate", # Employee, actor, etc.
    "internal_marketing_asset", # e.g., product mockup
]

# Risk levels by use case
USE_CASE_RISK_LEVELS = {
    "internal_marketing": "low",
    "internal_training": "low",
    "public_stock_image": "low",
    "public_facing_marketing": "medium",
    "external_communications": "medium",
    "synthetic_voice_for_ivrs": "medium",
    "deception_research": "high", # For internal red teaming
    "political_satire_internal": "high",
}

# Approval thresholds by risk
APPROVAL_THRESHOLDS = {
    "low": "single_operator",
    "medium": "dual_approval",
    "high": "ethics_committee_review", # Even stricter than dual_approval
}

# Retention policy constant
RETENTION_POLICY_YEARS = 7
RETENTION_POLICY_TEXT = f"Consent documents, generation requests, and forensic logs must be stored securely for a minimum of {RETENTION_POLICY_YEARS} years (or as per superseding legal requirements)."


# --- Schemas ---

class GenerationRequest(BaseModel):
    """
    A request to generate a new synthetic media asset.
    This object is checked against the policy.
    """
    subject_name: str = Field(..., description="Name of the person/subject, or 'stock_face'.")
    subject_category: str = Field(..., description="Category of the subject (e.g., 'minor', 'consenting_adult_corporate').")
    use_case: str = Field(..., description="Intended use case (e.g., 'internal_marketing', 'public_facing_marketing').")
    requesting_operator: str = Field(..., description="The user ID of the operator making the request.")
    consent_proof_id: Optional[str] = Field(None, description="Reference ID for the stored consent document, if applicable.")


class PolicyCheckResult(BaseSchema):
    """
    The result of a policy check on a GenerationRequest.
    """
    is_allowed: bool = Field(..., description="Whether this generation is allowed or blocked.")
    is_blocked: bool = Field(..., description="Opposite of is_allowed, for clarity.")
    reason: str = Field(..., description="The reason for the decision (e.g., 'BLOCKED: Subject is a minor').")
    risk_level: str = Field("none", description="The assessed risk level (low, medium, high).")
    approval_required: str = Field("none", description="The approval workflow required (e.g., 'single_operator', 'dual_approval').")
    retention_policy_applies: bool = Field(False, description="Indicates that the standard retention policy applies.")
    request_details: GenerationRequest


# --- Policy Logic ---

def check_generation_policy(request: GenerationRequest) -> PolicyCheckResult:
    """
    Checks a synthetic media generation request against the configured policies.

    Args:
        request: A GenerationRequest object detailing the job.

    Returns:
        A PolicyCheckResult object with the decision and rationale.
    """
    logger.info(f"Checking generation policy for request from {request.requesting_operator}...")

    # 1. Check for hard blocks (Req 9 - Blocked)
    if request.subject_category in BLOCKED_SUBJECT_CATEGORIES:
        reason = f"BLOCKED: Generation of subject category '{request.subject_category}' is prohibited."
        logger.warning(reason)
        return PolicyCheckResult(
            is_allowed=False,
            is_blocked=True,
            reason=reason,
            risk_level="high", # Blocked actions are implicitly high risk
            approval_required="n/a",
            request_details=request
        )

    # 2. Check for sensitive categories that default to blocked without consent
    if request.subject_category in SENSITIVE_SUBJECT_CATEGORIES and not request.consent_proof_id:
        reason = f"BLOCKED: Subject category '{request.subject_category}' is sensitive and requires a valid consent_proof_id."
        logger.warning(reason)
        return PolicyCheckResult(
            is_allowed=False,
            is_blocked=True,
            reason=reason,
            risk_level="high",
            approval_required="n/a",
            request_details=request
        )

    # 3. Check for unknown use case
    if request.use_case not in USE_CASE_RISK_LEVELS:
        reason = f"BLOCKED: Unknown use_case '{request.use_case}'. Must be one of {list(USE_CASE_RISK_LEVELS.keys())}."
        logger.warning(reason)
        return PolicyCheckResult(
            is_allowed=False,
            is_blocked=True,
            reason=reason,
            risk_level="medium", # Unknown use case is a risk
            approval_required="n/a",
            request_details=request
        )
        
    # 4. Check for consent on categories that require it
    if request.subject_category == "consenting_adult_corporate" and not request.consent_proof_id:
        reason = f"BLOCKED: Subject category '{request.subject_category}' requires a 'consent_proof_id'."
        logger.warning(reason)
        return PolicyCheckResult(
            is_allowed=False,
            is_blocked=True,
            reason=reason,
            risk_level="medium",
            approval_required="n/a",
            request_details=request
        )

    # 5. Passed blocks, determine risk and approval (Req 9 - Approval threshold)
    risk_level = USE_CASE_RISK_LEVELS.get(request.use_case, "low")
    approval_workflow = APPROVAL_THRESHOLDS.get(risk_level, "single_operator")

    reason = f"ALLOWED: Risk level '{risk_level}'. Requires '{approval_workflow}'."
    logger.info(reason)
    
    # (Req 9 - Retention)
    # The retention policy applies to all allowed generations
    retention_applies = True 

    return PolicyCheckResult(
        is_allowed=True,
        is_blocked=False,
        reason=reason,
        risk_level=risk_level,
        approval_required=approval_workflow,
        retention_policy_applies=retention_applies,
        request_details=request
    )

def get_retention_policy_text() -> str:
    """Returns the human-readable data retention policy."""
    return RETENTION_POLICY_TEXT