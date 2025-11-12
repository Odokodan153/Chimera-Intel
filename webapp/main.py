from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Query,
    WebSocket,
    WebSocketDisconnect,
    FastAPI,
    Request
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Dict
import uuid
import logging
from functools import lru_cache

# Core Chimera Intel imports
from chimera_intel.core.database import get_db_connection as get_db_sync
from chimera_intel.core.database import get_db
from chimera_intel.core import schemas, models # <-- schemas is imported
from chimera_intel.core.negotiation import NegotiationEngine

# Import all routers
from chimera_intel.webapp.routers import auth
from chimera_intel.webapp.routers import the_eye_api
# This import was updated in my previous response
from chimera_intel.webapp.routers.auth import get_current_active_user
# NEW: Import project_manager function
from chimera_intel.core.project_manager import get_project_config_by_name


# --- App, Template, and Static File Setup ---
app = FastAPI()
app.mount("/static", StaticFiles(directory="webapp/static"), name="static")
app.mount("/lib", StaticFiles(directory="lib"), name="lib") 
templates = Jinja2Templates(directory="webapp/templates")
# --- End Setup ---


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@lru_cache()
def get_engine():
    model_path = "models/negotiation_intent_model"
    try:
        return NegotiationEngine(model_path=model_path)
    except Exception as e:
        logger.error(f"FATAL: Could not load transformer model at {model_path}: {e}")
        return NegotiationEngine()


# --- Your Existing Negotiation Router ---
router = APIRouter()

@router.post(
    "/negotiations",
    response_model=schemas.Negotiation,
    status_code=status.HTTP_201_CREATED,
)
async def create_negotiation(
    negotiation: schemas.NegotiationCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user),
):
    # (Your existing create_negotiation logic)
    try:
        session_id = str(uuid.uuid4())
        # Note: Your schema/main.py was mixing Pydantic and SQLAlchemy models.
        # This assumes NegotiationSession is the SQLAlchemy model.
        db_negotiation = models.NegotiationSession(
            id=session_id, subject=negotiation.subject
        )
        db.add(db_negotiation)

        for participant in negotiation.participants:
            db_participant = models.NegotiationParticipant(
                session_id=session_id,
                participant_id=participant.participant_id,
                participant_name=participant.participant_name,
            )
            db.add(db_participant)
        db.commit()
        db.refresh(db_negotiation)
        logger.info(
            f"Multi-party negotiation session created successfully with ID: {session_id}"
        )
        return db_negotiation
    except Exception as e:
        logger.error(f"Database error while creating negotiation session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create negotiation session.",
        )


@router.post(
    "/negotiations/{negotiation_id}/messages",
    response_model=schemas.AnalysisResponse,
)
async def analyze_new_message(
    negotiation_id: str,
    message: schemas.MessageCreate,
    # --- THIS IS THE CORRECTED PART ---
    # It now correctly uses the SimulationScenario schema
    simulation_scenario: schemas.SimulationScenario, 
    # --- END CORRECTION ---
    db: Session = Depends(get_db),
    engine: NegotiationEngine = Depends(get_engine),
    current_user: models.User = Depends(get_current_active_user),
):
    """
    Analyzes a new message and returns a structured response including
    analysis, recommendation, and simulation.
    """
    db_negotiation = (
        db.query(models.NegotiationSession)
        .filter(models.NegotiationSession.id == negotiation_id)
        .first()
    )
    if not db_negotiation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Negotiation session not found",
        )
    try:
        analysis = engine.analyze_message(message.content)

        db_message = models.MessageModel( # Use the SQLAlchemy model
            id=str(uuid.uuid4()),
            negotiation_id=negotiation_id,
            sender_id=message.sender_id,
            content=message.content,
            analysis=analysis,
        )
        db.add(db_message)
        db.commit()

        recent_messages = (
            db.query(models.MessageModel)
            .filter(models.MessageModel.negotiation_id == negotiation_id)
            .order_by(models.MessageModel.timestamp.desc())
            .limit(20)
            .all()
        )
        history = [
            {
                "sender_id": msg.sender_id,
                "content": msg.content,
                "analysis": msg.analysis,
            }
            for msg in reversed(recent_messages)
        ]

        recommendation = engine.recommend_tactic(history)
        
        # Now we can run the simulation
        # The engine expects a dict, so we convert the Pydantic model
        simulation = engine.simulate_outcome(simulation_scenario.model_dump())

        logger.info(f"Message in negotiation {negotiation_id} analyzed successfully.")

        return {
            "message_id": db_message.id,
            "analysis": analysis,
            "recommended_tactic": recommendation,
            "simulation": simulation,
        }
    except Exception as e:
        logger.error(f"Error analyzing message for negotiation {negotiation_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while analyzing the message.",
        )


@router.get("/negotiations/{negotiation_id}", response_model=schemas.Negotiation)
async def get_negotiation_history(
    negotiation_id: str,
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: models.User = Depends(get_current_active_user),
):
    # (Your existing get_negotiation_history logic)
    db_negotiation = (
        db.query(models.NegotiationSession)
        .filter(models.NegotiationSession.id == negotiation_id)
        .offset(skip)
        .limit(limit)
        .first()
    )
    if not db_negotiation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Negotiation session not found",
        )
    return db_negotiation


@router.websocket("/ws/{negotiation_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    negotiation_id: str,
    token: str = Query(...),
    db: Session = Depends(get_db),
    engine: NegotiationEngine = Depends(get_engine),
):
    # (Your existing websocket logic)
    await websocket.accept()
    await websocket.send_text("WebSocket connection established.")
    await websocket.close()


# --- Include All Routers ---
app.include_router(router, tags=["Negotiation"]) 
app.include_router(auth.router, prefix="/api", tags=["Authentication"]) 
app.include_router(the_eye_api.router, prefix="/api", tags=["The Eye OSINT"]) 

# --- HTML Template Endpoints ---
@app.get("/", include_in_schema=False)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/project/{project_name}", include_in_schema=False)
async def read_project_detail(request: Request, project_name: str):
    project_config = get_project_config_by_name(project_name) 
    if not project_config:
        raise HTTPException(status_code=404, detail="Project not found")

    return templates.TemplateResponse(
        "project_detail.html",
        {"request": request, "project": project_config},
    )

# --- NEW: Add endpoints for the remaining templates ---
@app.get("/login", include_in_schema=False)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register", include_in_schema=False)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/profile", include_in_schema=False)
async def profile_page(request: Request):
    return templates.TemplateResponse("profile.html", {"request": request})

@app.get("/negotiation", include_in_schema=False)
async def negotiation_page(request: Request):
    return templates.TemplateResponse("negotiation_chat.html", {"request": request})

@app.get("/simulator", include_in_schema=False)
async def simulator_page(request: Request):
    return templates.TemplateResponse("simulator.html", {"request": request})

@app.get("/chat", include_in_schema=False)
async def chat_page(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request})