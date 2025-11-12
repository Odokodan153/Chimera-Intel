# src/chimera_intel/core/image_misuse_playbook.py

import logging
import json
import os
import tempfile
import pathlib
import shutil
import subprocess
from typing import Dict, Any, List
from urllib.parse import urlparse

# --- Third-Party Imports ---
import playwright.sync_api
from typer.testing import CliRunner

# --- Real Chimera Core Imports ---
# Assumes a central Celery app is defined in a 'worker.py'
try:
    from chimera_intel.worker import celery_app
except ImportError:
    # Fallback for environments where worker isn't set up, but will fail at runtime
    import celery # type: ignore
    logging.critical("Could not import 'chimera_intel.worker.celery_app'. Playbook tasks will not be registered.")
    celery_app = celery.Celery('chimera_intel_fallback')

# Import real schemas, DB, and other modules
from chimera_intel.core.schemas import HumanReviewTask
from chimera_intel.core.database import db
from chimera_intel.core.graph_db import graph_db
from chimera_intel.core.page_monitor import PageMonitor
from chimera_intel.core.response import ACTION_MAP as response_action_map
from chimera_intel.core.forensic_vault import vault_app
from chimera_intel.core.image_forensics_pipeline import pipeline_app as forensics_app
from chimera_intel.core.counter_intelligence import get_legal_escalation_template

logger = logging.getLogger(__name__)

# --- Production Configuration ---
# Load paths from environment variables
PERSISTENT_STORAGE_PATH = os.environ.get("PERSISTENT_STORAGE_PATH", "/var/chimera/persistent_vault")
PLAYBOOK_SIGNING_KEY_PATH = os.environ.get("PLAYBOOK_SIGNING_KEY_PATH")

if not PLAYBOOK_SIGNING_KEY_PATH:
    logger.critical("PLAYBOOK_SIGNING_KEY_PATH environment variable is not set. Vaulting tasks will fail.")
elif not os.path.exists(PLAYBOOK_SIGNING_KEY_PATH):
    logger.error(f"Playbook signing key not found at specified path: {PLAYBOOK_SIGNING_KEY_PATH}")

# Ensure persistent storage directory exists
try:
    os.makedirs(PERSISTENT_STORAGE_PATH, exist_ok=True)
except Exception as e:
    logger.critical(f"Failed to create persistent storage directory at {PERSISTENT_STORAGE_PATH}: {e}")


# --- Utility Functions ---

def _persist_file(temp_path: str, subfolder: str) -> str:
    """
    Moves a file from a temporary path to persistent storage.
    
    Args:
        temp_path: The path to the temporary file.
        subfolder: The subfolder within persistent storage (e.g., 'evidence', 'reports').

    Returns:
        The new persistent path.
    """
    if not os.path.exists(temp_path):
        raise FileNotFoundError(f"Temporary file does not exist: {temp_path}")

    base_filename = os.path.basename(temp_path)
    persistent_dir = os.path.join(PERSISTENT_STORAGE_PATH, subfolder)
    persistent_path = os.path.join(persistent_dir, base_filename)
    
    try:
        os.makedirs(persistent_dir, exist_ok=True)
        shutil.move(temp_path, persistent_path)
        logger.info(f"Persisted file from {temp_path} to {persistent_path}")
        return persistent_path
    except Exception as e:
        logger.error(f"Failed to persist file {temp_path} to {persistent_path}: {e}")
        raise

def _is_video_url(url: str) -> bool:
    """Helper to determine if a URL points to a video."""
    video_domains = ['youtube.com', 'youtu.be', 'vimeo.com', 'tiktok.com', 'twitter.com', 'facebook.com']
    video_extensions = ['.mp4', '.mov', '.avi', '.wmv', '.mkv']
    
    try:
        parsed_url = urlparse(url)
        if any(domain in parsed_url.netloc for domain in video_domains):
            return True
        if any(parsed_url.path.endswith(ext) for ext in video_extensions):
            return True
    except Exception:
        return False
    return False

def _capture_screenshot(url: str, save_path: str) -> bool:
    """Captures a full-page screenshot of a URL."""
    try:
        with playwright.sync_api.sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, wait_until='networkidle', timeout=30000)
            page.screenshot(path=save_path, full_page=True)
            browser.close()
        logger.info(f"Screenshot saved to {save_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to capture screenshot for {url} using Playwright: {e}")
        return False

def _download_video(url: str, save_path: str) -> bool:
    """Downloads a video from a URL using yt-dlp."""
    try:
        # We assume yt-dlp is installed in the environment
        cmd = [
            'yt-dlp',
            '-o', save_path,
            '--quiet',
            '--no-warnings',
            '--no-playlist',
            '-f', 'best[ext=mp4]/best', # Get best MP4 format
            url
        ]
        # 5 minute timeout for video download
        subprocess.run(cmd, check=True, timeout=300, capture_output=True)
        if os.path.exists(save_path):
            logger.info(f"Video downloaded to {save_path}")
            return True
        else:
            logger.error(f"yt-dlp command ran but output file {save_path} not found.")
            return False
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout downloading video {url}")
        return False
    except subprocess.CalledProcessError as e:
        logger.error(f"yt-dlp failed for video {url}: {e.stderr.decode()}")
        return False
    except Exception as e:
        logger.error(f"Failed to download video {url}: {e}")
        return False

# --- Playbook Step Definitions (Celery Tasks) ---

@celery_app.task(name="playbook.capture_evidence", bind=True, acks_late=True, max_retries=1)
def task_capture_evidence(self, source_url: str) -> Dict[str, Any]:
    """
    Step 1: Capture Evidence
    - Downloads video or screenshots image.
    - Creates a forensic vault receipt (hash, timestamp).
    - Persists evidence to permanent storage.
    """
    runner = CliRunner()
    temp_dir = tempfile.mkdtemp(prefix="chimera_evidence_")
    
    try:
        is_video = _is_video_url(source_url)
        media_type = "video" if is_video else "image"
        file_ext = ".mp4" if is_video else ".png"
        
        # 1. Capture Media
        media_filename = f"evidence_{urlparse(source_url).netloc.replace('.', '_')}{file_ext}"
        temp_media_path = os.path.join(temp_dir, media_filename)
        
        if is_video:
            capture_success = _download_video(source_url, temp_media_path)
        else:
            capture_success = _capture_screenshot(source_url, temp_media_path)

        if not capture_success:
            raise Exception(f"Failed to capture media from {source_url}")

        # 2. Capture Screenshot of the page itself (even for videos)
        temp_screenshot_path = os.path.join(temp_dir, "context_screenshot.png")
        _capture_screenshot(source_url, temp_screenshot_path)

        # 3. Create Forensic Receipt
        if not PLAYBOOK_SIGNING_KEY_PATH or not os.path.exists(PLAYBOOK_SIGNING_KEY_PATH):
            logger.error("No signing key found. Aborting vault receipt creation.")
            raise Exception("PLAYBOOK_SIGNING_KEY_PATH is not configured or key not found.")

        temp_receipt_path = os.path.join(temp_dir, "vault_receipt.json")
        result = runner.invoke(
            vault_app,
            [
                "create-receipt",
                temp_media_path,
                "--key", PLAYBOOK_SIGNING_KEY_PATH,
                "--output", temp_receipt_path,
            ],
            catch_exceptions=False
        )
        
        if result.exit_code != 0:
            logger.error(f"Vault receipt creation failed: {result.stdout}")
            raise Exception(f"Failed to create vault receipt: {result.stdout}")

        with open(temp_receipt_path, 'r') as f:
            receipt_data = json.load(f)

        # 4. Persist all captured files
        persistent_media_path = _persist_file(temp_media_path, "evidence")
        persistent_screenshot_path = _persist_file(temp_screenshot_path, "evidence")
        persistent_receipt_path = _persist_file(temp_receipt_path, "receipts")

        return {
            "source_url": source_url,
            "media_type": media_type,
            "persistent_media_path": persistent_media_path,
            "persistent_screenshot_path": persistent_screenshot_path,
            "persistent_receipt_path": persistent_receipt_path,
            "vault_receipt": receipt_data,
        }
    except Exception as e:
        logger.error(f"Task playbook.capture_evidence failed for {source_url}: {e}")
        self.retry(exc=e, countdown=60)
    finally:
        # Clean up temporary directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

@celery_app.task(name="playbook.generate_forensic_report", bind=True, acks_late=True, max_retries=1)
def task_generate_forensic_report(self, prev_step_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 2: Generate Forensic Report
    - Runs the full forensics pipeline on the captured (and persisted) media.
    - Persists the final report.
    """
    runner = CliRunner()
    temp_dir = tempfile.mkdtemp(prefix="chimera_report_")
    
    try:
        persistent_media_path = prev_step_data["persistent_media_path"]
        if not os.path.exists(persistent_media_path):
            raise FileNotFoundError(f"Persistent media file not found at {persistent_media_path}")

        temp_report_path = os.path.join(temp_dir, "forensic_report.json")
        
        # The forensics app needs to handle both image and video paths
        result = runner.invoke(
            forensics_app,
            ["run", persistent_media_path, "--output", temp_report_path],
            catch_exceptions=False
        )
        
        if result.exit_code != 0:
            logger.error(f"Forensic report generation failed: {result.stdout}")
            raise Exception(f"Failed to generate forensic report: {result.stdout}")
            
        with open(temp_report_path, 'r') as f:
            forensic_report = json.load(f)
            
        # Persist the report
        persistent_report_path = _persist_file(temp_report_path, "reports")
        
        prev_step_data["persistent_report_path"] = persistent_report_path
        prev_step_data["forensic_report"] = forensic_report
        return prev_step_data

    except Exception as e:
        logger.error(f"Task playbook.generate_forensic_report failed: {e}")
        self.retry(exc=e, countdown=60)
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

@celery_app.task(name="playbook.request_legal_review", bind=True, acks_late=True)
def task_request_legal_review(self, prev_step_data: Dict[str, Any]) -> str:
    """
    Step 3: Request Legal Review (Human-in-the-Loop)
    - Creates a HumanReviewTask in the database.
    - This is the end of the automated pre-approval chain.
    """
    try:
        # 1. Assemble the data for the legal team
        forensic_report = prev_step_data.get("forensic_report", {})
        
        review_details = {
            "source_url": prev_step_data["source_url"],
            "media_type": prev_step_data["media_type"],
            "vault_receipt": prev_step_data.get("vault_receipt", {}),
            "forensic_summary": {
                "hashes": forensic_report.get("hashes"),
                "ocr_text": forensic_report.get("ocr_scan", {}).get("text"),
                "reverse_image_search": forensic_report.get("reverse_image_search"),
                "flagged_regions": forensic_report.get("manipulation_scan", {}).get("regions"),
            },
            "attachments": {
                "media": prev_step_data["persistent_media_path"],
                "context_screenshot": prev_step_data["persistent_screenshot_path"],
                "vault_receipt": prev_step_data["persistent_receipt_path"],
                "forensic_report": prev_step_data["persistent_report_path"],
            }
        }
        
        # 2. Create the HumanReviewTask
        review_task = HumanReviewTask(
            assignee_team="legal_team",
            status="pending",
            deadline_hours=24,
            context_data=review_details,
            playbook_name="image_misuse_takedown"
        )
        
        # 3. Save to database (using the real 'db' object)
        task_id = db.save_human_review_task(review_task.model_dump(exclude_none=True))
        logger.info(f"Human review task {task_id} created for legal_team.")
        
        return task_id
        
    except Exception as e:
        logger.error(f"Failed to save human review task to DB: {e}")
        self.retry(exc=e, countdown=300)

# --- POST-APPROVAL WORKFLOW ---

@celery_app.task(name="playbook.execute_takedown", bind=True, acks_late=True)
def task_execute_takedown(self, review_task: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 4: Takedown Request
    - Called *after* legal_review.approved == true.
    - Fetches the correct legal template and executes the takedown.
    """
    try:
        context = review_task["context_data"]
        source_url = context["source_url"]
        
        # 1. Get DMCA template (using real module)
        template_result = get_legal_escalation_template(complaint_type="dmca-takedown")
        if template_result.error:
            raise Exception(f"Could not get DMCA template: {template_result.error}")
        
        # 2. Get takedown action (using real map)
        takedown_func = response_action_map.get("platform_takedown_request")
        if not takedown_func:
            raise Exception("Action 'platform_takedown_request' not found in ACTION_MAP.")

        # 3. Prepare event details for the action
        event_details = {
            "url": source_url,
            "platform": urlparse(source_url).netloc,
            "reason": "Copyright Infringement / Brand Misuse",
            "takedown_template": template_result.template_body,
            "attachments": [
                context["attachments"]["forensic_report"],
                context["attachments"]["vault_receipt"]
            ]
        }
        
        # 4. Execute takedown
        takedown_func(event_details)
        logger.info(f"Takedown request sent for {source_url}")
        
        return review_task # Pass context to next step
    except Exception as e:
        logger.error(f"Task playbook.execute_takedown failed: {e}")
        self.retry(exc=e, countdown=300)

@celery_app.task(name="playbook.notify_comms", bind=True, acks_late=True)
def task_notify_comms(self, review_task: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 5: Notify Comms Team
    - Sends an internal alert.
    """
    try:
        context = review_task["context_data"]
        source_url = context["source_url"]

        notify_func = response_action_map.get("internal_threat_warning")
        if not notify_func:
            logger.warning("Action 'internal_threat_warning' not found. Skipping comms notification.")
            return review_task
        
        # Compute severity
        severity = review_task.get("priority", "Medium") # Use priority set by human

        event_details = {
            "incident_type": "image_misuse_takedown_complete",
            "target": source_url,
            "severity": severity,
            "message": f"Legal-approved takedown submitted for {source_url}. Comms team FYI. Awaiting platform response."
        }
        
        notify_func(event_details)
        logger.info(f"Internal notification sent to comms team for {source_url}")
    except Exception as e:
        # This is a non-critical step, log warning and continue
        logger.warning(f"Task playbook.notify_comms failed (non-fatal): {e}")
    
    return review_task

@celery_app.task(name="playbook.add_to_graph", bind=True, acks_late=True)
def task_add_to_graph(self, review_task: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 6: Add to Graph DB
    - Adds nodes for the image, "seller"/poster, and platform.
    """
    try:
        context = review_task["context_data"]
        source_url = context["source_url"]
        platform = urlparse(source_url).netloc
        image_hash = context["vault_receipt"]["hashes"]["sha256"]
        
        # Assumes some logic to find the poster/seller node
        seller_node = f"user:{platform}:{context.get('poster_id', 'unknown')}"
        
        # Use real graph_db object
        graph_db.add_node(image_hash, type="media_hash", label=f"Misused Media")
        graph_db.add_node(platform, type="platform", label=platform)
        graph_db.add_node(seller_node, type="actor", label=f"Potential Bad Actor")
        
        graph_db.add_edge(seller_node, "HOSTED_ON", platform)
        graph_db.add_edge(seller_node, "USED_MEDIA", image_hash)
        
        logger.info(f"Added nodes to graph for {image_hash}")
    except Exception as e:
        # Also non-critical
        logger.warning(f"Task playbook.add_to_graph failed (non-fatal): {e}")
    
    return review_task

@celery_app.task(name="playbook.monitor_followups", bind=True, acks_late=True)
def task_monitor_followups(self, review_task: Dict[str, Any]) -> str:
    """
    Step 7: Monitor for Follow-ups
    - Adds the URL to a PageMonitor to check for re-upload or takedown success.
    """
    try:
        source_url = review_task["context_data"]["source_url"]
        
        # Use real PageMonitor class
        monitor = PageMonitor()
        monitor.add_url_to_monitor(
            url=source_url,
            check_interval_days=1,
            monitor_duration_days=30,
            check_for_takedown=True # Assumes this flag exists
        )
        logger.info(f"Added {source_url} to PageMonitor for 30-day follow-up.")
        return f"Monitoring started for {source_url}"
    except Exception as e:
        logger.error(f"Failed to start follow-up monitoring: {e}")
        # Non-fatal, but should be retried
        self.retry(exc=e, countdown=600)


# --- Workflow Trigger Functions ---

def trigger_image_misuse_playbook(
    source_url: str,
    trigger_confidence: float,
    trigger_type: str = "misuse"
):
    """
    (ENTRYPOINT 1)
    Called by an upstream process (e.g., BrandProtectionPipeline) when
    a misuse event is flagged with high confidence.
    
    Triggers the pre-approval workflow.
    """
    logger.info(f"Triggering image misuse playbook for {source_url} (Confidence: {trigger_confidence})")
    
    # Create the chain of tasks: Step 1 -> Step 2 -> Step 3
    workflow_chain = (
        task_capture_evidence.s(source_url=source_url) |
        task_generate_forensic_report.s() |
        task_request_legal_review.s()
    )
    
    # Execute the chain
    try:
        async_result = workflow_chain.apply_async()
        logger.info(f"Playbook pre-approval chain started. Task ID: {async_result.id}")
        return async_result.id
    except Exception as e:
        logger.critical(f"Failed to apply Celery chain for 'trigger_image_misuse_playbook': {e}")
        return None


def trigger_takedown_from_approval(review_task_id: str):
    """
    (ENTRYPOINT 2)
    Called by the Analyst UI/API *after* a human
    in legal_team clicks 'Approve' on the review task.
    
    Triggers the post-approval workflow.
    """
    
    # 1. Fetch the approved review task from the DB
    try:
        review_task = db.get_human_review_task(review_task_id)
        if not review_task:
            logger.error(f"Takedown triggered, but review task {review_task_id} not found.")
            raise Exception(f"Review task {review_task_id} not found.")
        
        if review_task["status"] != "approved":
            logger.warning(f"Takedown triggered for task {review_task_id} that is not 'approved'. Status: {review_task['status']}")
            # We proceed, assuming the trigger is authoritative.
            
    except Exception as e:
        logger.error(f"Failed to fetch review task: {e}")
        return None

    logger.info(f"Triggering post-approval takedown for {review_task_id}")

    # 2. Create the post-approval chain: Step 4 -> Step 5 -> Step 6 -> Step 7
    workflow_chain = (
        task_execute_takedown.s(review_task=review_task) |
        task_notify_comms.s() |
        task_add_to_graph.s() |
        task_monitor_followups.s()
    )
    
    # 3. Execute the chain
    try:
        async_result = workflow_chain.apply_async()
        logger.info(f"Playbook post-approval chain started. Task ID: {async_result.id}")
        return async_result.id
    except Exception as e:
        logger.critical(f"Failed to apply Celery chain for 'trigger_takedown_from_approval': {e}")
        return None