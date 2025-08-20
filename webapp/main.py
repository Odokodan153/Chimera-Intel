"""
Main FastAPI application for the Chimera Intel web dashboard.
"""

import os
import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import logging
from chimera_intel.core.footprint import gather_footprint_data
from chimera_intel.core.web_analyzer import gather_web_analysis_data
from chimera_intel.core.business_intel import get_news_gnews, scrape_google_patents
from chimera_intel.core.schemas import BusinessIntelData, BusinessIntelResult
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.grapher import generate_knowledge_graph
from chimera_intel.core.utils import is_valid_domain
from chimera_intel.core.database import get_scan_history

logger = logging.getLogger(__name__)

app = FastAPI(title="Chimera Intel API")
app.mount("/static", StaticFiles(directory="webapp/static"), name="static")
templates = Jinja2Templates(directory="webapp/templates")


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request) -> HTMLResponse:
    """Serves the main index.html page."""
    return templates.TemplateResponse("index.html", {"request": request})


# --- NEW ENDPOINT START ---


@app.get("/api/history", response_class=JSONResponse)
async def api_get_history() -> JSONResponse:
    """API endpoint to fetch all scan history."""
    logger.info("Fetching scan history from database.")
    history_records = get_scan_history()
    return JSONResponse(content=history_records)


# --- NEW ENDPOINT END ---


@app.post("/api/scan")
async def api_scan(request: Request) -> JSONResponse:
    """API endpoint to initiate a scan."""
    # ... (existing code for this function remains the same)

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
        if scan_type == "footprint":
            scan_results_model = await gather_footprint_data(domain)
            scan_results = scan_results_model.model_dump()
        elif scan_type == "web_analyzer":
            scan_results_model = await gather_web_analysis_data(domain)
            scan_results = scan_results_model.model_dump()
        elif scan_type == "business_intel":
            news_task = get_news_gnews(domain, API_KEYS.gnews_api_key)
            patents_task = scrape_google_patents(domain)
            news_results, patents_results = await asyncio.gather(
                news_task, patents_task
            )

            intel_data = BusinessIntelData(
                financials="Not provided for web scan",
                news=news_results,
                patents=patents_results,
            )
            scan_results_model = BusinessIntelResult(
                company=domain, business_intel=intel_data
            )
            scan_results = scan_results_model.model_dump(exclude_none=True)
        else:
            return JSONResponse(
                content={"error": "Invalid scan type selected."}, status_code=400
            )
        if not scan_results:
            return JSONResponse(
                content={"error": "Scan failed to produce results."}, status_code=500
            )
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
