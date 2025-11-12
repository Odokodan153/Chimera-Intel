import asyncio
import logging
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    BackgroundTasks,
    Body,
    status,
    Request  # <-- ADDED
)
from fastapi.templating import Jinja2Templates  # <-- ADDED
from typing import Dict, Any, List
from sqlalchemy.orm import Session

# --- Real Core Imports ---
from chimera_intel.core.database import (
    get_db, # SQLAlchemy Session
    get_db_connection, # Psycopg2 Connection
    save_scan_to_db,
    get_scan_history_for_target
)
from chimera_intel.core.project_manager import (
    list_projects,
    get_project_config_by_name
)
from chimera_intel.core.footprint import gather_footprint_data, perform_port_scan
from chimera_intel.core.web_analyzer import gather_web_analysis_data
from chimera_intel.core.recon import query_passive_dns
from chimera_intel.core.graph_db import (
    graph_db_instance,
    add_graph_node,
    add_graph_relationship
)
from chimera_intel.core import schemas, models
from chimera_intel.webapp.routers.auth import get_current_active_user

router = APIRouter()
logger = logging.getLogger(__name__)

# --- ADDED: Template Configuration ---
templates = Jinja2Templates(directory="webapp/templates")

# --- Background Task Definitions ---

def run_scan_task(domain: str, module: str, project_name: str, user_id: int):
    """
    The "real" background task for running a scan and saving it.
    """
    try:
        logger.info(f"Background task starting: module={module}, domain={domain}")
        if module == "footprint":
            results_model = asyncio.run(gather_footprint_data(domain))
        elif module == "web_analyzer":
            results_model = asyncio.run(gather_web_analysis_data(domain))
        else:
            logger.warning(f"Unknown scan module '{module}' requested.")
            return

        results_dict = results_model.model_dump()
        
        # Get project_id using the psycopg2 connection
        db_conn = get_db_connection()
        cursor = db_conn.cursor()
        cursor.execute("SELECT id FROM projects WHERE name = %s", (project_name,))
        record = cursor.fetchone()
        project_id = record[0] if record else None
        cursor.close()
        db_conn.close()

        # Save to DB using the psycopg2 connection
        save_scan_to_db(
            target=domain,
            module=module,
            data=results_dict,
            user_id=user_id,
            project_id=project_id,
        )
        logger.info(f"Background task complete and saved to DB for: {domain}")

    except Exception as e:
        logger.error(f"Background scan task failed for {domain} ({module}): {e}")

def pivot_task(node_id: str, node_type: str, action: str):
    """
    The "real" background task for a graph pivot action.
    """
    try:
        logger.info(f"Pivot task starting: action={action}, node={node_id}")
        if action == "find_subdomains" and node_type == "Domain":
            results = asyncio.run(query_passive_dns(indicator=node_id))
            if results.records:
                with graph_db_instance._driver.session() as session:
                    for record in results.records:
                        if record.hostname and record.hostname != node_id:
                            session.write_transaction(
                                add_graph_node, "Domain", {"id": record.hostname, "name": record.hostname, "is_subdomain": True}, "id"
                            )
                            session.write_transaction(
                                add_graph_relationship, "Domain", node_id, "Domain", record.hostname, "PDNS_RELATED"
                            )
            logger.info(f"Pivot task 'find_subdomains' complete for {node_id}")

        elif action == "scan_ports" and node_type == "IPAddress":
            results = asyncio.run(perform_port_scan(ip_address=node_id))
            if results.open_ports:
                 with graph_db_instance._driver.session() as session:
                    port_str = ", ".join([f"{p}/{s}" for p, s in results.open_ports.items()])
                    props = {"id": f"ports_for_{node_id}", "ports": port_str, "name": f"Ports: {node_id}"}
                    session.write_transaction(add_graph_node, "PortInfo", props, "id")
                    session.write_transaction(add_graph_relationship, "IP", node_id, "PortInfo", props["id"], "HAS_PORTS")
            logger.info(f"Pivot task 'scan_ports' complete for {node_id}")

    except Exception as e:
        logger.error(f"Pivot task failed for {node_id} ({action}): {e}")


# --- API Endpoints ---

@router.get("/projects", response_model=List[schemas.Project])
async def get_projects(
    db: Session = Depends(get_db), # SQLAlchemy Session
    current_user: models.User = Depends(get_current_active_user)
):
    """
    Gets the list of projects for the current user.
    (Real Implementation)
    """
    try:
        # This uses the "real" function from project_manager.py
        project_names = list_projects() 
        project_list = []
        for name in project_names:
            config = get_project_config_by_name(name)
            if config:
                # Synthesize a schemas.Project object
                project_list.append(
                    schemas.Project(
                        id=config.project_name, # Use name as ID
                        name=config.project_name,
                        description=f"Domain: {config.domain}",
                        owner_id=current_user.id # From auth
                    )
                )
        return project_list
    except Exception as e:
        logger.error(f"Failed to list projects: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve projects.")


@router.post("/project/{project_name}/scan")
async def run_scan(
    project_name: str,
    background_tasks: BackgroundTasks,
    scan_type: str = Body(..., alias="scan_type"), 
    current_user: models.User = Depends(get_current_active_user),
):
    """
    Triggers a new background scan (footprint or web_analyzer).
    (Real Implementation)
    """
    project_config = get_project_config_by_name(project_name) 
    if not project_config:
        raise HTTPException(status_code=404, detail="Project not found")
    
    domain = project_config.domain
    if not domain:
         raise HTTPException(status_code=400, detail="Project has no domain to scan.")

    if scan_type not in ["footprint", "web_analyzer"]:
        raise HTTPException(status_code=400, detail="Invalid scan_type.")

    background_tasks.add_task(
        run_scan_task, 
        domain, 
        scan_type, 
        project_name, 
        current_user.id
    )
    return {"status": "success", "message": f"Scan '{scan_type}' started on {project_name}"}


@router.get("/project/{project_name}/graph_page", include_in_schema=False) # <-- MODIFIED
async def get_project_graph_page( # <-- MODIFIED
    project_name: str,
    request: Request, # <-- ADDED
    current_user: models.User = Depends(get_current_active_user)
):
    """
    Fetches the graph data and renders the graph_viewer.html template
    for the iframe.
    (Real Implementation)
    """
    project_config = get_project_config_by_name(project_name)
    if not project_config:
        raise HTTPException(status_code=404, detail="Project not found")
    target_domain = project_config.domain

    query = """
    MATCH (s:Domain {id: $domain})-[r*1..2]-(t)
    WITH COLLECT(s) + COLLECT(t) as nodes, COLLECT(r) as rels
    UNWIND nodes as n
    UNWIND rels as r
    WITH COLLECT(DISTINCT {id: n.id, label: n.name, group: labels(n)[0], title: n.id}) as nodes,
         COLLECT(DISTINCT {from: startNode(r).id, to: endNode(r).id, label: type(r)}) as edges
    RETURN nodes, edges
    """
    try:
        results = graph_db_instance.execute_query(query, {"domain": target_domain})
        
        if not results or not results[0].get('nodes'):
            nodes_data = [{"id": target_domain, "label": target_domain, "group": "Domain", "title": target_domain}]
            edges_data = []
        else:
            nodes_data = results[0].get('nodes', [])
            edges_data = results[0].get('edges', [])
        
        context = {
            "request": request,
            "project_name": project_name,
            "nodes_json": nodes_data,
            "edges_json": edges_data
        }
        return templates.TemplateResponse("graph_viewer.html", context)

    except Exception as e:
        logger.error(f"Failed to query/render graph for {project_name}: {e}")
        # Return a template with an error
        return templates.TemplateResponse("graph_viewer.html", {
            "request": request,
            "project_name": project_name,
            "nodes_json": [],
            "edges_json": [],
            "error": str(e)
        })


@router.post("/graph/pivot")
async def graph_pivot(
    background_tasks: BackgroundTasks,
    payload: Dict[str, Any] = Body(...),
    current_user: models.User = Depends(get_current_active_user)
):
    """
    Triggers a background pivot action from the graph.
    (Real Implementation)
    """
    node_id = payload.get("node_id")
    node_type = payload.get("node_type")
    action = payload.get("action")

    if not all([node_id, node_type, action]):
        raise HTTPException(status_code=400, detail="Missing pivot parameters")

    background_tasks.add_task(pivot_task, node_id, node_type, action)
    return {"status": "success", "message": f"Pivot action '{action}' on '{node_id}' started."}


@router.get("/project/{project_name}/history")
async def get_project_history(
    project_name: str,
    current_user: models.User = Depends(get_current_active_user)
):
    """
    Fetches the scan history for a project's domain.
    (Real Implementation)
    """
    project_config = get_project_config_by_name(project_name) 
    if not project_config:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # This is the real function from database.py
    history = get_scan_history_for_target(target=project_config.domain) 
    
    if not history:
        return {"html": "<p>No scan history found for this project.</p>"}
    
    # Format as simple HTML table as expected by project_detail.html
    html = "<table><thead><tr><th>Date</th><th>Scan Type</th><th>Status</th></tr></thead><tbody>"
    for item in history:
        # Handle potential timezone-aware datetime
        ts = item['timestamp']
        if isinstance(ts, str):
            # If it's already a string, just use it
            ts_str = ts
        elif ts.tzinfo:
            ts_str = ts.astimezone().strftime('%Y-%m-%d %H:%M %Z')
        else:
            ts_str = ts.strftime('%Y-%m-%d %H:%M')
            
        html += f"<tr><td>{ts_str}</td><td>{item['module']}</td><td>Completed</td></tr>"
    html += "</tbody></table>"
    
    return {"html": html}