"""
Main FastAPI application for the Chimera Intel web dashboard.

This script initializes and configures the FastAPI application, mounts the static
file directories, and defines the API endpoints for serving the frontend and
handling scan requests.
"""

import os
import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Dict, Any

# --- CORRECTED Absolute Imports ---
# Import core functions and utilities from the main package
from chimera_intel.core.footprint import gather_footprint_data
from chimera_intel.core.database import initialize_database
from chimera_intel.core.grapher import generate_knowledge_graph
# Import the central domain validation function
from chimera_intel.core.utils import is_valid_domain

# Initialize the database once when the web application starts
initialize_database()

# Create the FastAPI application instance
app = FastAPI(title="Chimera Intel API")

# Mount the 'static' directory to serve CSS, JS, and other static assets.
app.mount("/static", StaticFiles(directory="webapp/static"), name="static")
# Point to the 'templates' directory for HTML page rendering.
templates = Jinja2Templates(directory="webapp/templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request) -> HTMLResponse:
    """
    Serves the main index.html page for the web dashboard.

    This is the root endpoint that users will land on when they visit the application.

    Args:
        request (Request): The incoming request object from FastAPI.

    Returns:
        HTMLResponse: The rendered HTML page.
    """
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/scan")
async def api_scan(request: Request) -> JSONResponse:
    """
    API endpoint to initiate a footprint scan for a given domain.

    This endpoint receives a JSON payload with a 'domain', validates it, runs the
    asynchronous footprint scan, generates a knowledge graph, and returns the
    results.

    Args:
        request (Request): The incoming POST request, expected to have a JSON body
                           containing a 'domain' key.

    Returns:
        JSONResponse: The scan results or an error message in JSON format.
    """
    try:
        data = await request.json()
        domain = data.get('domain')
        
        # --- INPUT VALIDATION STEP ---
        if not is_valid_domain(domain):
            return JSONResponse(content={"error": "Invalid domain format provided."}, status_code=400)

        # Run the core async scan function
        scan_results_model = await gather_footprint_data(domain)
        scan_results = scan_results_model.model_dump()
        
        # Ensure the directory for graphs exists
        graph_dir = os.path.join('webapp', 'static', 'graphs')
        os.makedirs(graph_dir, exist_ok=True)
        
        # Generate the graph after a successful scan
        graph_filename = f"{domain.replace('.', '_')}_graph.html"
        graph_filepath = os.path.join(graph_dir, graph_filename)
        generate_knowledge_graph(scan_results, graph_filepath)
        
        # Add the graph's URL to the results for the frontend
        scan_results['graph_url'] = str(request.url_for('static', path=f'graphs/{graph_filename}'))
        
        return JSONResponse(content=scan_results)
    
    except Exception as e:
        # Generic error handler for any unexpected issues
        return JSONResponse(content={"error": f"An unexpected server error occurred: {e}"}, status_code=500)