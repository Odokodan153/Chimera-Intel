"""
API Router for 🧿 The Eye (Phase 3: Productization)
Provides API access for the web dashboard and external clients.
"""

import asyncio
import logging 
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict

from chimera_intel.core.the_eye import TheEye
logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/api/v1/eye",
    tags=["The Eye - OSINT Platform"],
)

class InvestigationRequest(BaseModel):
    identifier: str
    # In a real app, tenant_id would come from the auth dependency
    tenant_id: str = "default_tenant" 

class InvestigationRun(BaseModel):
    run_id: str
    status: str
    target: str
    exposure_score: float

# --- In-Memory "Task" Storage (replace with a real DB/Redis for production) ---
# This is a simple way to track running tasks without a full task broker
_running_tasks: Dict[str, str] = {}


def _run_investigation_task(identifier: str, tenant_id: str, run_id: str):
    """
    The background task that The Eye will execute.
    """
    try:
        logger.info(f"Starting background run {run_id} for {identifier}")
        # Initialize The Eye with the specific tenant ID
        eye_instance = TheEye(tenant_id=tenant_id)
        
        # This is a synchronous call within the async task runner
        asyncio.run(eye_instance.run(identifier))
        
        _running_tasks[run_id] = "complete"
        logger.info(f"Background run {run_id} complete.")
    except Exception as e:
        logger.error(f"Background run {run_id} failed: {e}")
        _running_tasks[run_id] = f"error: {e}"

# --- API Endpoints ---

@router.post("/run", status_code=202)
async def start_investigation(
    request: InvestigationRequest, 
    background_tasks: BackgroundTasks,
    # tenant_id: str = Depends(get_current_tenant_id) # Use this in prod
):
    """
    Start a new, asynchronous investigation for "The Eye".
    """
    # For this example, we use the tenant_id from the request
    tenant_id = request.tenant_id
    
    # Use the target identifier as a simple run ID (or generate a UUID)
    run_id = f"{tenant_id}:{request.identifier}"

    if _running_tasks.get(run_id) == "running":
        raise HTTPException(status_code=409, detail="Investigation already in progress.")

    _running_tasks[run_id] = "running"
    # Add the long-running job to the background
    background_tasks.add_task(
        _run_investigation_task,
        request.identifier,
        tenant_id,
        run_id
    )
    
    return {"message": "Investigation started.", "run_id": run_id}


@router.get("/status/{run_id}")
async def get_investigation_status(run_id: str):
    """
    Check the status of a running investigation.
    """
    status = _running_tasks.get(run_id)
    if not status:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    
    return {"run_id": run_id, "status": status}


@router.get("/report/{run_id}")
async def get_investigation_report(
    run_id: str,
    # tenant_id: str = Depends(get_current_tenant_id) # Use this in prod
):
    """
    Retrieve the final JSON report for a completed investigation.
    (This assumes GraphDB is updated to find runs by tenant_id)
    """
    # This is a simplified example.
    # In a real app, you'd fetch the JSON report data from your GraphDB
    # using the `run_id` and `tenant_id`.
    
    if _running_tasks.get(run_id) != "complete":
        raise HTTPException(status_code=404, detail="Report not ready or run does not exist.")

    # Mock fetching from DB
    # eye_instance = TheEye(tenant_id="default")
    # report_json = eye_instance.graph_db.get_run_json(run_id)
    # return report_json
    
    return {"message": "Report data would be here.", "run_id": run_id, "status": "complete"}


@router.get("/health")
async def get_system_health():
    """
    Perform a health check on The Eye and its dependencies.
    """
    try:
        # Use a "default" tenant for a system-wide health check
        eye_instance = TheEye(tenant_id="system_health")
        health_report = eye_instance.check_system_health()
        if not health_report.healthy:
            return HTTPException(status_code=503, detail=health_report.model_dump())
        return health_report.model_dump()
    except Exception as e:
        return HTTPException(status_code=500, detail=f"Health check failed: {e}")