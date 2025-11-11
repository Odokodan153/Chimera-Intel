# src/chimera_intel/core/local_db_service.py

"""
Local, self-contained SQLite database service.

Implements the same function interface as the main 'database.py' 
but uses a local SQLite file (./local_evidence_vault.db), 
requiring no external services.

(Updated to include get_scans_by_target)
"""
import sqlite3
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
DB_FILE = "./local_evidence_vault.db"

def _create_connection():
    """Create a database connection to the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
    except sqlite3.Error as e:
        logger.error(f"Error connecting to local SQLite DB: {e}")
    return conn

def _init_db():
    """Initialize the database tables."""
    conn = _create_connection()
    if conn:
        try:
            cursor = conn.cursor()
            # This table mimics the one used by 'evidence_vault.py'
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                module TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                data TEXT
            );
            """)
            # --- ADDED: Index for efficient querying by target/module ---
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_target_module
            ON scan_results (target, module);
            """)
            conn.commit()
            logger.info(f"Local SQLite DB initialized at {DB_FILE}")
        except sqlite3.Error as e:
            logger.error(f"Error creating table: {e}")
        finally:
            conn.close()

# Run init once on import
_init_db()

def save_scan_to_db(
    target: str,
    module: str,
    data: Dict[str, Any],
    scan_id: str
):
    """Saves a scan result (or vault item) to the local SQLite DB."""
    conn = _create_connection()
    if conn:
        try:
            sql = ''' INSERT OR REPLACE INTO scan_results
                      (id, target, module, timestamp, data)
                      VALUES(?,?,?,?,?) '''
            cursor = conn.cursor()
            
            # Ensure timestamp exists, default if not
            ts = data.get('timestamp', datetime.now(timezone.utc).isoformat())
            if 'timestamp' not in data:
                 data['timestamp'] = ts
                 
            cursor.execute(sql, (
                scan_id,
                target,
                module,
                ts,
                json.dumps(data) # Store the data dict as a JSON string
            ))
            conn.commit()
            logger.debug(f"Successfully saved {scan_id} to local SQLite DB.")
        except sqlite3.Error as e:
            logger.error(f"Failed to save {scan_id} to local SQLite: {e}")
        finally:
            conn.close()

def get_scan_from_db(
    scan_id: str,
    module_name: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Retrieves a scan result (or vault item) from the local SQLite DB."""
    conn = _create_connection()
    if conn:
        try:
            cursor = conn.cursor()
            if module_name:
                cursor.execute(
                    "SELECT target, module, data FROM scan_results WHERE id = ? AND module = ?",
                    (scan_id, module_name)
                )
            else:
                cursor.execute(
                    "SELECT target, module, data FROM scan_results WHERE id = ?",
                    (scan_id,)
                )
            
            row = cursor.fetchone()
            if row:
                return {
                    "scan_id": scan_id, # Re-add scan_id for context
                    "target": row[0],
                    "module": row[1],
                    "data": json.loads(row[2]) # Re-load the JSON string into a dict
                }
        except sqlite3.Error as e:
            logger.error(f"Failed to retrieve {scan_id} from local SQLite: {e}")
        finally:
            conn.close()
    return None

# --- NEW FUNCTION ---
def get_scans_by_target(
    target: str,
    module: str
) -> List[Dict[str, Any]]:
    """
    Retrieves all scan results for a specific target and module.
    Used by EthicalGuardrails to find subject profiles.
    """
    conn = _create_connection()
    results = []
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, data FROM scan_results WHERE target = ? AND module = ?",
                (target, module)
            )
            rows = cursor.fetchall()
            for row in rows:
                results.append(json.loads(row[1])) # Return just the data blob
        except sqlite3.Error as e:
            logger.error(f"Failed to retrieve scans for target {target} from local SQLite: {e}")
        finally:
            conn.close()
    return results
# --- END NEW FUNCTION ---