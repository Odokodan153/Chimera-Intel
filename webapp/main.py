"""
Main FastAPI application for the Chimera Intel web dashboard.
"""

import os
import asyncio
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import logging
from chimera_intel.core.footprint import gather_footprint_data
from chimera_intel.core.web_analyzer import gather_web_analysis_data
from chimera_intel.core.utils import is_valid_domain
from chimera_intel.core.database import get_scan_history_for_target, save_scan_to_db
from chimera_intel.core.project_manager import (
    list_projects,
    get_project_config_by_name,
)
from chimera_intel.core.reporter import (
    generate_graph_report,
)
from chimera_intel.core.graph_actions import (
    run_graph_action,
)  # Import the new graph actions

logger = logging.getLogger(__name__)

app = FastAPI(title="Chimera Intel API")

# --- Setup for Static Files and Templates ---
# Ensures that the web app can find the CSS, JS, and HTML files.


app.mount("/static", StaticFiles(directory="webapp/static"), name="static")
templates = Jinja2Templates(directory="webapp/templates")


# --- HTML Page Routes ---


@app.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request):
    """Serves the main project dashboard page."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/project/{project_name}", response_class=HTMLResponse)
async def read_project_view(request: Request, project_name: str):
    """Serves the detailed view page for a single project."""
    project_config = get_project_config_by_name(project_name)
    if not project_config:
        raise HTTPException(status_code=404, detail="Project not found")
    return templates.TemplateResponse(
        "project_detail.html",
        {"request": request, "project": project_config.model_dump()},
    )


# --- API Endpoints ---


@app.get("/api/projects", response_class=JSONResponse)
async def api_get_projects():
    """API endpoint to fetch all project names."""
    return JSONResponse(content={"projects": list_projects()})


@app.get("/api/project/{project_name}/history", response_class=JSONResponse)
async def api_get_project_history(project_name: str):
    """API endpoint to fetch scan history for a specific project."""
    project_config = get_project_config_by_name(project_name)
    if not project_config or not project_config.domain:
        return JSONResponse(content=[])
    # A project's history is tied to its primary domain target

    history = get_scan_history_for_target(project_config.domain)
    return JSONResponse(content=history)


@app.post("/api/scan", response_class=JSONResponse)
async def api_run_scan(request: Request):
    """API endpoint to initiate a new scan for a project."""
    try:
        data = await request.json()
        domain = data.get("domain")
        scan_type = data.get("scan_type")

        logger.info(f"Received web API request for '{scan_type}' on '{domain}'")

        if not domain or not is_valid_domain(domain):
            raise HTTPException(status_code=400, detail="Invalid domain provided.")
        scan_results_model = None
        if scan_type == "footprint":
            scan_results_model = await gather_footprint_data(domain)
        elif scan_type == "web_analyzer":
            scan_results_model = await gather_web_analysis_data(domain)
        else:
            raise HTTPException(status_code=400, detail="Invalid scan type.")
        # Save to database and return

        results_dict = scan_results_model.model_dump(exclude_none=True)
        save_scan_to_db(target=domain, module=scan_type, data=results_dict)

        return JSONResponse(content={"status": "success", "scan_type": scan_type})
    except HTTPException as http_exc:
        # Re-raise HTTP exceptions to let FastAPI handle them

        raise http_exc
    except Exception as e:
        logger.error(
            f"An unexpected error occurred in api_run_scan: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=500, detail="An internal server error occurred."
        )


@app.get("/api/project/{project_name}/graph", response_class=FileResponse)
async def api_get_project_graph(project_name: str):
    """API endpoint to generate and return the project's entity graph."""
    project_config = get_project_config_by_name(project_name)
    if not project_config or not project_config.domain:
        raise HTTPException(status_code=404, detail="Project target not found.")
    output_dir = "temp_reports"
    os.makedirs(output_dir, exist_ok=True)
    graph_path = os.path.join(
        output_dir, f"{project_name.replace(' ', '_')}_graph.html"
    )

    # This is a synchronous function, so we run it in a thread to avoid blocking

    await asyncio.to_thread(generate_graph_report, project_config.domain, graph_path)

    if not os.path.exists(graph_path):
        raise HTTPException(
            status_code=500, detail="Failed to generate the graph report."
        )
    return FileResponse(graph_path)


@app.post("/api/graph/pivot", response_class=JSONResponse)
async def api_graph_pivot(request: Request):
    """
    API endpoint to perform a 'visual pivot' from the graph.
    This will run a new scan on a node and update the graph.
    """
    data = await request.json()
    node_id = data.get("node_id")
    node_type = data.get("node_type")
    action = data.get("action")

    result = await run_graph_action(node_id, node_type, action)

    return JSONResponse(content=result)
