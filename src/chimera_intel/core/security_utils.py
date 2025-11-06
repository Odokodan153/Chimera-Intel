"""
Security & Compliance Utilities for Chimera Intel.

Provides functions for:
- Auditing user actions
- Loading and validating consent (Rules of Engagement)
- Redacting PII from text
- Normalizing data for safe processing
"""

import os
import re
import json
import time
import logging
import yaml
from typing import Tuple, Optional, Any, Dict, List

# --- Audit Logging ---

# Load audit log path from environment, default to a local file
AUDIT_LOG_PATH = os.getenv("CHIMERA_AUDIT_LOG", "chimeraintel_audit.log")

# Configure a dedicated logger for audit trails
audit_logger = logging.getLogger("chimera_audit")
audit_logger.setLevel(logging.INFO)
if not audit_logger.hasHandlers():
    # Ensure handler is added only once
    handler = logging.FileHandler(AUDIT_LOG_PATH)
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    audit_logger.addHandler(handler)

def audit_event(user: str, action: str, target: str, consent_id: Optional[str], note: Optional[str] = None):
    """Logs a structured audit event to the audit trail."""
    entry = {
        "timestamp": int(time.time()),
        "user": user,
        "action": action,
        "target": target,
        "consent_id": consent_id,
        "note": note,
    }
    audit_logger.info(json.dumps(entry))

# --- Data Sanitization & Normalization ---

def _first_n(sample: Any, n: int = 5) -> List[Any]:
    """Safely get the first N items from a list or dict values."""
    if sample is None:
        return []
    if isinstance(sample, dict):
        return list(sample.values())[:n]
    try:
        return sample[:n]
    except Exception:
        return []

def normalize_ai_result(ai_result: Any) -> Tuple[Optional[str], str]:
    """Normalizes various AI result formats into a standard (error, text) tuple."""
    if ai_result is None:
        return ("AI returned None", "")
    if isinstance(ai_result, dict):
        err = ai_result.get("error") or ai_result.get("err")
        text = ai_result.get("analysis_text") or ai_result.get("text") or ai_result.get("content") or ""
        return (err, text)
    
    # Handle Pydantic models or other objects
    err = getattr(ai_result, "error", None)
    text = getattr(ai_result, "analysis_text", None) or getattr(ai_result, "analysis", None) or ""
    
    if not text and not err:
        text = str(ai_result) # Fallback
        
    return (err, text)

# Regex for common PII patterns
PII_PATTERNS = [
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", # Emails
    r"\+?\d{7,15}", # Phone numbers
]

def redact_personal_data(text: str) -> str:
    """Redacts common PII patterns from a block of text."""
    if not text:
        return text
    for p in PII_PATTERNS:
        text = re.sub(p, "[REDACTED]", text)
    return text

# --- Consent & Authorization (ROE) ---

def load_consent(path: str) -> Dict[str, Any]:
    """Loads a YAML or JSON consent/ROE file from disk."""
    with open(path, "r", encoding="utf-8") as f:
        if path.lower().endswith((".yaml", ".yml")):
            return yaml.safe_load(f)
        elif path.lower().endswith(".json"):
            return json.load(f)
        else:
            raise ValueError("Consent file must be a .json, .yaml, or .yml file.")

def check_consent_for_action(consent: Dict[str, Any], target: str, action: str) -> bool:
    """Validates if a given action is authorized for a specific target."""
    if not consent:
        return False
    
    # 1. Check target authorization
    targets = consent.get("authorized_targets", [])
    if "*" not in targets and target not in targets:
        return False # Target not explicitly listed or wildcarded
        
    # 2. Check action authorization
    if action not in consent.get("authorized_actions", []):
        return False # Action not explicitly authorized
        
    # 3. (Optional) Check time window
    now = int(time.time())
    valid_from = consent.get("valid_from_epoch", 0)
    valid_to = consent.get("valid_to_epoch", float('inf'))
    
    if not (valid_from <= now <= valid_to):
        return False # Outside the authorized time window

    return True