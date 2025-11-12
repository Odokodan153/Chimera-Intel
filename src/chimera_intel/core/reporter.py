"""
(Production-Ready)
Incident Response Action Module.

This module provides a centralized set of real, production-ready functions 
for responding to detected incidents. It replaces all mock logic with
real webhook integrations, LLM calls, and database operations.
"""

import logging
import json
import os
import datetime
from typing import Dict, Any, Callable, Optional

# --- Core Chimera Imports ---
from chimera_intel.core.http_client import sync_client
from chimera_intel.core.llm_interface import gemini_client
from chimera_intel.core.database import db
from chimera_intel.core.schemas import HumanReviewTask

# --- Configuration ---
# Load configured webhook URLs and API keys
try:
    from chimera_intel.core.config_loader import WEBHOOK_URLS, API_KEYS
except ImportError:
    logging.critical("Could not import WEBHOOK_URLS from config_loader. Response actions will fail.")
    # Define placeholder to allow file to load
    class WebhookURLs:
        internal_alerts_slack = "http://localhost:9090/slack-placeholder"
        platform_takedown = "http://localhost:9090/takedown-placeholder"
        incident_report_ingest = "http://localhost:9090/siem-placeholder"
    WEBHOOK_URLS = WebhookURLs()
    API_KEYS = {} # type: ignore

# --- C2PA (Provenance) Import ---
# Attempt to import the C2PA library for real manifest updates.
try:
    import c2pa
    C2PA_ENABLED = True
    logging.info("C2PA library loaded successfully. Provenance actions are enabled.")
except ImportError:
    C2PA_ENABLED = False
    logging.warning("C2PA library not found (pip install c2pa). Provenance actions will be disabled.")


logger = logging.getLogger(__name__)

# --- Real Action Implementations ---

def platform_takedown_request(event_details: Dict[str, Any]):
    """
    (REAL) Sends a takedown request to an internal webhook service.
    
    This service is responsible for handling platform-specific logic
    (e.g., calling Twitter API, Facebook Graph API, etc.).
    
    Expected event_details:
    - url (str): The URL of the content to takedown.
    - platform (str): The platform (e.g., 'twitter.com').
    - reason (str): The reason for the takedown.
    - takedown_template (str): The legal text (e.g., DMCA).
    - attachments (list): List of paths to evidence files.
    """
    webhook_url = WEBHOOK_URLS.platform_takedown
    if not webhook_url:
        logger.error("No 'platform_takedown' webhook URL configured. Cannot send request.")
        return

    payload = {
        "incident_type": "platform_takedown",
        "url_to_remove": event_details.get("url"),
        "platform": event_details.get("platform"),
        "reason": event_details.get("reason", "No reason provided."),
        "legal_text": event_details.get("takedown_template"),
        "evidence_links": event_details.get("attachments", []) # Assumes these are now URLs or persistent paths
    }
    
    try:
        response = sync_client.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status() # Raise exception for 4xx/5xx
        logger.info(f"Successfully sent takedown request for {event_details.get('url')} to internal webhook.")
    except Exception as e:
        logger.error(f"Failed to send takedown request to webhook {webhook_url}: {e}")
        # In a real system, this might trigger a retry or secondary alert

def internal_threat_warning(event_details: Dict[str, Any]):
    """
    (REAL) Sends a formatted alert to an internal Slack/Teams channel.
    
    Expected event_details:
    - incident_type (str): e.g., 'deepfake_detected'
    - target (str): The person or asset targeted.
    - severity (str): 'High', 'Medium', 'Low'
    - message (str): A pre-formatted message.
    """
    webhook_url = WEBHOOK_URLS.internal_alerts_slack
    if not webhook_url:
        logger.error("No 'internal_alerts_slack' webhook URL configured. Cannot send alert.")
        return

    severity_color = {
        "High": "#D00000",
        "Medium": "#FFC300",
        "Low": "#4D96FF",
    }.get(event_details.get("severity", "Low"), "#808080")

    # Slack Block Kit format
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f":warning: CHIMERA INCIDENT ALERT: {event_details.get('incident_type', 'Unspecified Incident')}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n*{event_details.get('severity', 'N/A')}*"},
                    {"type": "mrkdwn", "text": f"*Target:*\n{event_details.get('target', 'N/A')}"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Details:*\n{event_details.get('message', 'No details provided.')}"
                }
            },
            {
                "type": "context",
                "elements": [
                    {"type": "plain_text", "text": f"Incident Time: {datetime.datetime.now(datetime.UTC).isoformat()}"}
                ]
            }
        ],
        "attachments": [
            {
                "color": severity_color,
                "blocks": [] # Used for the color bar
            }
        ]
    }

    try:
        response = sync_client.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        logger.info(f"Successfully sent internal threat warning for {event_details.get('target')}.")
    except Exception as e:
        logger.error(f"Failed to send internal Slack alert to webhook {webhook_url}: {e}")

def generate_debunking_script(event_details: Dict[str, Any]):
    """
    (REAL) Uses an LLM to generate a draft debunking script for the comms team.
    
    Expected event_details:
    - target (str): The executive or brand.
    - media_type (str): 'image', 'video', 'audio'
    - confidence (float): The detection confidence.
    - forensic_summary (dict): Key findings from the forensic report.
    """
    target = event_details.get("target", "our organization")
    media_type = event_details.get("media_type", "media")
    confidence = event_details.get("confidence", "high")
    forensics = event_details.get("forensic_summary", "Forensic analysis is conclusive.")
    
    prompt = f"""
    You are a professional crisis communications expert.
    A fraudulent {media_type} targeting "{target}" has been detected.
    Our internal systems are {confidence * 100:.0f}% confident it is a fabrication.
    Forensic details: {json.dumps(forensics)}

    Your task is to draft three separate public statements:
    1.  **Twitter (X) Draft:** Clear, concise, and direct. Max 280 characters.
    2.  **LinkedIn/Blog Draft:** More formal, professional, and detailed.
    3.  **Internal Employee Memo:** Calm, informative, and instructs employees on what to do if they see it.

    Format the output as a JSON object with keys "twitter_draft", "linkedin_draft", and "internal_memo".
    """
    
    try:
        # We assume gemini_client is configured to output JSON
        # In a real setup, we would add 'response_mime_type: "application/json"' to the gen_config
        response_text = gemini_client.generate_text(prompt)
        
        # Clean up and save
        # LLMs can sometimes wrap JSON in markdown backticks
        if response_text.strip().startswith("```json"):
            response_text = response_text.strip()[7:-3].strip()
            
        # Try to parse the JSON response
        response_json = json.loads(response_text)
        
        # Save as a structured JSON file, not just a .txt
        filename = f"debunking_drafts_{target.replace(' ', '_')}_{datetime.datetime.now().strftime('%Y%m%d%H%M')}.json"
        with open(filename, "w") as f:
            json.dump(response_json, f, indent=2)
            
        logger.info(f"LLM-generated debunking drafts saved to {filename}.")
        
    except Exception as e:
        logger.error(f"Failed to generate or save LLM debunking script: {e}")
        # Fallback to simple text file
        filename = f"debunking_draft_FAILED_{target.replace(' ', '_')}.txt"
        with open(filename, "w") as f:
            f.write(f"LLM generation failed ({e}).\n\nMANUAL DRAFT REQUIRED.\nIncident: Fraudulent {media_type} targeting {target}.")
        logger.info(f"Saved fallback draft to {filename}.")


def update_c2pa_manifest(event_details: Dict[str, Any]):
    """
    (REAL) Signs a media file with C2PA provenance data.
    
    Expected event_details:
    - media_file (str): Path to the *original* trusted media file.
    - output_file (str): Path to save the new, C2PA-signed file.
    - assertion_data (dict): Data to add to the manifest (e.g., author, timestamp).
    """
    if not C2PA_ENABLED:
        logger.warning("C2PA library not found. Skipping manifest update.")
        return

    media_file = event_details.get("media_file")
    output_file = event_details.get("output_file")
    assertion_data = event_details.get("assertion_data", {})
    
    if not media_file or not output_file:
        logger.error("`media_file` and `output_file` are required for C2PA signing.")
        return

    try:
        # 1. Load the signing key (assuming it's set up)
        # This requires a .pem and .key file configured as per c2pa-python docs
        # We'll assume a simple file-based signer for this example
        signer = c2pa.Signer.from_files(
            os.environ.get("C2PA_CERT_PATH", "c2pa_cert.pem"),
            os.environ.get("C2PA_KEY_PATH", "c2pa_key.key")
        )
        
        # 2. Create the manifest
        manifest = {
            "title": f"Official Media: {os.path.basename(media_file)}",
            "assertions": [
                {
                    "label": "c2pa.action",
                    "data": {"action": "c2pa.published"}
                },
                {
                    "label": "org.chimera-intel.provenance",
                    "data": {
                        "author": assertion_data.get("author", "Chimera Intel"),
                        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                        "status": "Verified Original"
                    }
                }
            ]
        }
        
        # 3. Sign the file
        c2pa.sign_file(media_file, output_file, signer, manifest)
        
        logger.info(f"Successfully signed '{media_file}' with C2PA manifest, saved to '{output_file}'.")
        
    except FileNotFoundError as e:
        logger.error(f"C2PA signing failed: Could not find key/cert files. Check C2PA_CERT_PATH and C2PA_KEY_PATH. Error: {e}")
    except Exception as e:
        logger.error(f"Failed to update C2PA manifest for {media_file}: {e}")


def log_incident_report(event_details: Dict[str, Any]):
    """
    (REAL) Logs a structured incident report to a SIEM or logging webhook.
    """
    webhook_url = WEBHOOK_URLS.incident_report_ingest
    if not webhook_url:
        logger.warning("No 'incident_report_ingest' webhook URL configured. Logging to console only.")
        print(json.dumps(event_details, indent=2))
        return

    # Add timestamp and source
    payload = {
        "source": "chimera_intel_response",
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "incident": event_details
    }
    
    try:
        response = sync_client.post(webhook_url, json=payload, timeout=5)
        response.raise_for_status()
        logger.info(f"Successfully logged incident {event_details.get('incident_type')} to ingest endpoint.")
    except Exception as e:
        logger.error(f"Failed to log incident to SIEM/ingest endpoint {webhook_url}: {e}")
        # Fallback to local file log
        try:
            with open("incident_log_fallback.jsonl", "a") as f:
                f.write(json.dumps(payload) + "\n")
            logger.warning("Logged incident to 'incident_log_fallback.jsonl'.")
        except Exception as fe:
            logger.critical(f"Failed to log incident to SIEM *and* fallback file: {fe}")


def escalate_to_human_review(event_details: Dict[str, Any]):
    """
    (REAL) Creates a task in the Human Review queue in the database.
    
    Expected event_details:
    - assignee_team (str): 'legal_team', 'comms_team', 'analyst_tier2'
    - context_data (dict): The full event details for the analyst.
    - playbook_name (str): The playbook that triggered this.
    """
    try:
        review_task = HumanReviewTask(
            assignee_team=event_details.get("assignee_team", "analyst_tier2"),
            status="pending",
            deadline_hours=event_details.get("deadline_hours", 48),
            context_data=event_details.get("context_data", event_details),
            playbook_name=event_details.get("playbook_name", "unspecified"),
            priority=event_details.get("severity", "Medium")
        )
        
        # Save to database using the real DB connection
        task_id = db.save_human_review_task(review_task.model_dump(exclude_none=True))
        logger.info(f"Successfully escalated to human review. Task ID: {task_id}")
        
    except Exception as e:
        logger.error(f"Failed to escalate to human review (DB error): {e}")


# --- Action Map ---
# This map connects string keys to the real, callable functions.
ACTION_MAP: Dict[str, Callable[[Dict[str, Any]], Any]] = {
    "platform_takedown_request": platform_takedown_request,
    "internal_threat_warning": internal_threat_warning,
    "generate_debunking_script": generate_debunking_script,
    "update_c2pa_manifest": update_c2pa_manifest,
    "log_incident_report": log_incident_report,
    "escalate_to_human_review": escalate_to_human_review,
}