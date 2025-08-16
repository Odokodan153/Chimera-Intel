"""
Main FastAPI application for the Chimera Intel web dashboard.
"""

import os
import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Dict, Any
import logging
from chimera_intel.core.footprint import gather_footprint_data
from chimera_intel.core.web_analyzer import gather_web_analysis_data
from chimera_intel.core.business_intel import run_business_intel
from chimera_intel.core.grapher import generate_knowledge_graph
from chimera_intel.core.utils import is_valid_domain

logger = logging.getLogger(__name__)

# --- FastAPI Application Initialization ---

app = FastAPI(title="Chimera Intel API")
app.mount("/static", StaticFiles(directory="webapp/static"), name="static")
templates = Jinja2Templates(directory="webapp/templates")


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request) -> HTMLResponse:
    """Serves the main index.html page."""
    logger.info("Serving root page to client %s", request.client.host)
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/scan")
async def api_scan(request: Request) -> JSONResponse:
    """
    API endpoint to initiate a scan based on user selection.
    """
    scan_results = None
    try:
        data = await request.json()
        domain = data.get("domain")
        scan_type = data.get("scan_type")

        logger.info("Received '%s' scan request for '%s'", scan_type, domain)

        if not is_valid_domain(domain):
            logger.warning("Invalid domain format received: '%s'", domain)
            return JSONResponse(
                content={"error": "Invalid domain format provided."}, status_code=400
            )
        # --- CHANGE: Use an if/elif block to call the correct function ---

        if scan_type == "footprint":
            scan_results_model = await gather_footprint_data(domain)
            scan_results = scan_results_model.model_dump()
        elif scan_type == "web_analyzer":
            scan_results_model = await gather_web_analysis_data(domain)
            scan_results = scan_results_model.model_dump()
        elif scan_type == "business_intel":
            # run_business_intel is synchronous, so we need to run it in an executor
            # to avoid blocking the async event loop.

            loop = asyncio.get_running_loop()
            # We pass a simplified version of the function to the executor

            scan_results = await loop.run_in_executor(
                None, lambda: run_business_intel_sync_wrapper(domain)
            )
        else:
            return JSONResponse(
                content={"error": "Invalid scan type selected."}, status_code=400
            )
        if not scan_results:
            return JSONResponse(
                content={"error": "Scan failed to produce results."}, status_code=500
            )
        # Generate a graph for footprint scans

        if scan_type == "footprint":
            graph_dir = os.path.join("webapp", "static", "graphs")
            os.makedirs(graph_dir, exist_ok=True)
            graph_filename = f"{domain.replace('.', '_')}_graph.html"
            graph_filepath = os.path.join(graph_dir, graph_filename)
            generate_knowledge_graph(scan_results, graph_filepath)
            scan_results["graph_url"] = str(
                request.url_for("static", path=f"graphs/{graph_filename}")
            )
        logger.info("Successfully completed scan for '%s'", domain)
        return JSONResponse(content=scan_results)
    except Exception as e:
        logger.error("An unexpected server error occurred: %s", e, exc_info=True)
        return JSONResponse(
            content={"error": "An unexpected server error occurred."}, status_code=500
        )


# --- Helper function to run the synchronous business_intel scan ---


def run_business_intel_sync_wrapper(company_name: str) -> Dict[str, Any]:
    """
    A simple wrapper to call the synchronous run_business_intel function
    and return its dictionary result, suitable for use with run_in_executor.
    """
    # This is a simplified call; we're not handling tickers or output files here.

    from chimera_intel.core.config_loader import API_KEYS
    from chimera_intel.core.schemas import BusinessIntelData, BusinessIntelResult

    intel_data = BusinessIntelData(
        financials="Not provided for web scan",
        news=run_business_intel.__globals__["get_news_gnews"](
            company_name, API_KEYS.gnews_api_key
        ),
        patents=run_business_intel.__globals__["scrape_google_patents"](company_name),
    )
    results_model = BusinessIntelResult(company=company_name, business_intel=intel_data)
    return results_model.model_dump(exclude_none=True)
