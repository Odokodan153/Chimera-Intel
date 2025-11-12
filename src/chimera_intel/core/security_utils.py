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
from cryptography.fernet import Fernet, InvalidToken
import base64
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.console import console
import logging
import yaml
from typing import Tuple, Optional, Any, Dict, List
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel

# Import user management and config
from chimera_intel.core.user_manager import UserManager
from chimera_intel.core.config_loader import ConfigLoader
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

_FERNET_INSTANCE = None

def get_pii_encryption_key() -> str:
    """
    Retrieves the PII encryption key from the central config.
    
    Raises:
        ValueError: If the key is not set or is not valid Fernet key.
    """
    # Assumes API_KEYS (from config_loader) has an attribute 'pii_encryption_key'
    key = getattr(API_KEYS, 'pii_encryption_key', None)
    
    if not key:
        raise ValueError("PII_ENCRYPTION_KEY is not set in config or .env file. "
                         "Cannot perform PII operations.")
    
    # Fernet keys must be 32 bytes and URL-safe base64 encoded.
    # This block validates the key's integrity before use.
    try:
        decoded_key = base64.urlsafe_b64decode(key.encode())
        if len(decoded_key) != 32:
             raise ValueError("PII_ENCRYPTION_KEY must be a 32-byte key.")
    except Exception as e:
        raise ValueError(f"PII_ENCRYPTION_KEY is not a valid URL-safe base64 key: {e}")
        
    return key

def _get_fernet() -> Fernet:
    """
    Initializes and returns a singleton Fernet instance for encryption/decryption.
    
    This ensures we only load and validate the key once.
    """
    global _FERNET_INSTANCE
    if _FERNET_INSTANCE is None:
        try:
            key = get_pii_encryption_key()
            _FERNET_INSTANCE = Fernet(key)
        except ValueError as e:
            console.print(f"[bold red]Security Fatal Error:[/bold red] {e}")
            raise
    return _FERNET_INSTANCE

def encrypt_pii(text: str) -> bytes:
    """
    Encrypts a plaintext string into Fernet-encrypted bytes.
    
    Args:
        text: The plaintext string to encrypt.
        
    Returns:
        The encrypted data as bytes.
        
    Raises:
        ValueError: If encryption fails (e.g., key is not initialized).
    """
    if not text:
        return None
    try:
        fernet = _get_fernet()
        return fernet.encrypt(text.encode('utf-8'))
    except Exception as e:
        console.print(f"[bold red]Encryption Failed:[/bold red] {e}")
        # Propagate exception to be caught by the calling function in humint.py
        raise ValueError(f"Encryption failed: {e}")

def decrypt_pii(data: bytes) -> str:
    """
    Decrypts Fernet-encrypted bytes back into a plaintext string.
    
    Args:
        data: The encrypted bytes to decrypt.
        
    Returns:
        The decrypted plaintext string.
        
    Raises:
        ValueError: If decryption fails (e.g., invalid token, wrong key).
    """
    if not data:
        return None
    try:
        fernet = _get_fernet()
        return fernet.decrypt(data).decode('utf-8')
    except InvalidToken:
        console.print(f"[bold red]Decryption Failed:[/bold red] Invalid token or key. Data may be corrupt or key may be wrong.")
        raise ValueError("Decryption failed: Invalid token or key.")
    except Exception as e:
        console.print(f"[bold red]Decryption Failed:[/bold red] {e}")
        raise ValueError(f"Decryption failed: {e}")
    


# Load config to get JWT secret
config = ConfigLoader().load_config()
SECRET_KEY = config.get('jwt_secret_key', 'DEFAULT_SECRET_KEY_REPLACE_ME')
ALGORITHM = "HS256"
OAUTH2_SCHEME = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

user_manager = UserManager()

class TokenData(BaseModel):
    username: Optional[str] = None

async def get_current_user(token: str = Depends(OAUTH2_SCHEME)):
    """
    Dependency that validates a JWT token and returns the user.
    (This is based on your webapp/routers/auth.py)
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = user_manager.get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_tenant_id(user: dict = Depends(get_current_user)) -> str:
    """
    NEW: Real Multi-Tenant Dependency (Phase 3)
    
    Gets the currently authenticated user and returns their tenant_id.
    This function is used to secure API endpoints.
    """
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not associated with a valid tenant."
        )
    return tenant_id