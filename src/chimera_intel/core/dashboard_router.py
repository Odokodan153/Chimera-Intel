"""
FastAPI router for serving the interactive BI dashboard.
"""
import typer
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from chimera_intel.core.dashboard_service import get_dashboard_charts
from chimera_intel.core.project_manager import get_project
from chimera_intel.core.utils import console, save_or_print_results

dashboard_router = APIRouter()
dashboard_app = typer.Typer()
templates = Jinja2Templates(directory="webapp/templates")


@dashboard_router.get("/project/{project_name}", response_class=HTMLResponse)
async def serve_dashboard(request: Request, project_name: str):
    """Serves the main dashboard HTML page for a project."""
    try:
        project = get_project(project_name)
        if not project.target_name:
            return HTMLResponse(
                "Project has no target. Set a target first.", status_code=404
            )
        return templates.TemplateResponse(
            "dashboard.html",
            {"request": request, "project_name": project_name},
        )
    except Exception as e:
        return HTMLResponse(str(e), status_code=404)


@dashboard_router.get("/api/data/{project_name}")
async def get_dashboard_data(project_name: str):
    """API endpoint to fetch formatted chart data."""
    project = get_project(project_name)
    if not project.target_name:
        return {"error": "Project has no target."}

    # Fetch and format data from the dashboard service
    charts_data = get_dashboard_charts(project.target_name)
    return {"project_name": project_name, "charts": charts_data}


@dashboard_app.command("export")
def export_dashboard_data(
    target: str = typer.Argument(..., help="Target name to export data for."),
):
    """Exports the raw dashboard JSON data to the console."""
    console.print(f"[bold cyan]Exporting dashboard data for {target}...[/]")
    charts_data = get_dashboard_charts(target)
    save_or_print_results(charts_data, None)