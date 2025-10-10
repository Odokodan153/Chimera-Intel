import os
import sys
import asyncio
import subprocess
from fastapi import (
    FastAPI,
    Request,
    Depends,
    status,
    Form,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from datetime import timedelta, datetime
import logging

# Adjust path to import from the core Chimera Intel library

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from src.chimera_intel.core.user_manager import (
    get_password_hash,
    verify_password,
    create_access_token,
    get_current_user,
)
from src.chimera_intel.core.database import (
    get_user_from_db,
    create_user_in_db,
    get_scan_history,
    initialize_database,
)
from src.chimera_intel.core.schemas import User
from src.chimera_intel.core.project_manager import list_projects
from webapp.routers import negotiation, simulator as simulator_router

# Configure structured logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --- FastAPI App Initialization ---


app = FastAPI()

# Include API routers

app.include_router(negotiation.router, prefix="/api/v1", tags=["negotiation"])
app.include_router(simulator_router.router, prefix="/api/v1", tags=["simulator"])

# Mount static files and templates

static_path = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_path), name="static")
templates_path = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_path)


@app.on_event("startup")
def on_startup():
    """Ensures the database is initialized when the application starts."""
    initialize_database()


# --- Authentication Routes ---


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login_for_access_token(
    request: Request, username: str = Form(...), password: str = Form(...)
):
    user = get_user_from_db(username)
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password"},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=timedelta(minutes=30)
    )
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        samesite="strict",
    )
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key="access_token")
    return response


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
async def register_user(
    request: Request, username: str = Form(...), password: str = Form(...)
):
    if get_user_from_db(username):
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Username already exists"},
            status_code=status.HTTP_409_CONFLICT,
        )
    hashed_password = get_password_hash(password)
    create_user_in_db(username, hashed_password)
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)


# --- WebSocket for Live Scan Output ---


@app.websocket("/ws/scan")
async def websocket_scan_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        module = data.get("module")
        target = data.get("target")

        if not module or not target:
            await websocket.send_text("Error: Missing module or target.")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        command = ["chimera", "scan", module, "run", target]
        await websocket.send_text(f"🚀 Starting '{' '.join(command)}'...\n")

        process = await asyncio.create_subprocess_exec(
            *command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        async def stream_output(stream, prefix=""):
            while stream and not stream.at_eof():
                line = await stream.readline()
                if line:
                    await websocket.send_text(f"{prefix}{line.decode().strip()}")

        await asyncio.gather(
            stream_output(process.stdout), stream_output(process.stderr, "ERROR: ")
        )

        await process.wait()
        await websocket.send_text("\n✅ Scan complete.")
    except WebSocketDisconnect:
        logger.info("Client disconnected from scan WebSocket")
    except Exception as e:
        logger.error(f"An unexpected error occurred in the scan WebSocket: {e}")
        await websocket.send_text(f"An unexpected error occurred: {e}")
    finally:
        await websocket.close()


# --- Main Application Routes ---


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, current_user: User = Depends(get_current_user)):
    """Redirects to the dashboard if logged in, otherwise to login."""
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)


@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard(
    request: Request, current_user: User = Depends(get_current_user)
):
    """Serves the main dashboard page."""
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    all_scans = get_scan_history()
    projects = list_projects()

    # Process data for the activity chart

    scans_by_day = {}
    for i in range(7):
        day = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
        scans_by_day[day] = 0
    for scan in all_scans:
        day = scan["timestamp"].strftime("%Y-%m-%d")
        if day in scans_by_day:
            scans_by_day[day] += 1
    chart_labels = list(reversed(list(scans_by_day.keys())))
    chart_data = list(reversed(list(scans_by_day.values())))

    dashboard_data = {
        "total_projects": len(projects),
        "total_scans": len(all_scans),
        "recent_scans": all_scans[:10],
        "projects": projects,
        "chart_labels": chart_labels,
        "chart_data": chart_data,
    }

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": current_user, "data": dashboard_data},
    )


@app.get("/negotiate", response_class=HTMLResponse)
def get_negotiation_chat(
    request: Request, current_user: User = Depends(get_current_user)
):
    """Serves the real-time negotiation chat page."""
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(
        "negotiation_chat.html", {"request": request, "user": current_user}
    )


@app.get("/simulator", response_class=HTMLResponse)
def get_negotiation_simulator(
    request: Request, current_user: User = Depends(get_current_user)
):
    """Serves the web-based negotiation training simulator."""
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(
        "simulator.html", {"request": request, "user": current_user}
    )
