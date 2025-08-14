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

# Configure static files and HTML templates directories
# This tells FastAPI where to find files like CSS, JavaScript, and HTML templates.
app.mount("/static", StaticFiles(directory="webapp/static"), name="static")
templates = Jinja2Templates(directory="webapp/templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request) -> HTMLResponse:
    """
    Serves the main index.html page when a user visits the root URL.
    
    Args:
        request (Request): The incoming request object from FastAPI.

    Returns:
        HTMLResponse: The rendered HTML page.
    """
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/scan")
async def api_scan(request: Request) -> JSONResponse:
    """
    API endpoint that accepts scan requests from the frontend.
    This function is fully asynchronous, allowing it to handle long-running scans
    without blocking the server.

    Args:
        request (Request): The incoming POST request, expected to have a JSON body.

    Returns:
        JSONResponse: The scan results or an error message in JSON format.
    """
    try:
        data = await request.json()
        domain = data.get('domain')
        
        # --- INPUT VALIDATION STEP ---
        # Before proceeding, validate the domain received from the client.
        # This is a critical security and stability measure.
        if not is_valid_domain(domain):
            return JSONResponse(content={"error": "Invalid domain format provided."}, status_code=400)

        # Directly call our core async function to perform the scan
        scan_results_model = await gather_footprint_data(domain)
        # Convert the Pydantic model to a dictionary for JSON serialization
        scan_results = scan_results_model.model_dump()
        
        # Ensure the directory for graphs exists
        graph_dir = os.path.join('webapp', 'static', 'graphs')
        os.makedirs(graph_dir, exist_ok=True)
        
        # Generate the graph after a successful scan
        graph_filename = f"{domain.replace('.', '_')}_graph.html"
        graph_filepath = os.path.join(graph_dir, graph_filename)
        generate_knowledge_graph(scan_results, graph_filepath)
        
        # Add the graph's URL to the results so the frontend can display a link
        scan_results['graph_url'] = request.url_for('static', path=f'graphs/{graph_filename}')
        
        return JSONResponse(content=scan_results)
    
    except Exception as e:
        # Generic error handler for any unexpected issues
        return JSONResponse(content={"error": f"An unexpected server error occurred: {e}"}, status_code=500)