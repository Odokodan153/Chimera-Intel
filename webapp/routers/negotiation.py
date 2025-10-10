from fastapi import APIRouter, Depends, HTTPException, status, Query, WebSocket
from sqlalchemy.orm import Session
from typing import List, Optional
import uuid
import json
import logging
from functools import lru_cache

# Core Chimera Intel imports

from chimera_intel.core.database import get_db
from chimera_intel.core import schemas, models

# Updated import to use the plugin's engine

from chimera_negotiation.engine import NegotiationEngine

# Configure structured logging for production

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@lru_cache()
def get_engine():
    """
    Initializes and returns a cached instance of the NegotiationEngine.
    The model is loaded only once to avoid performance bottlenecks.
    """
    model_path = "models/negotiation_intent_model"
    try:
        return NegotiationEngine(model_path=model_path)
    except Exception as e:
        logger.error(f"FATAL: Could not load transformer model at {model_path}: {e}")
        logger.warning(
            "Resilience Alert: Falling back to the placeholder Naive Bayes model."
        )
        return NegotiationEngine()


router = APIRouter()


@router.post(
    "/negotiations",
    response_model=schemas.Negotiation,
    status_code=status.HTTP_201_CREATED,
)
def create_negotiation(
    negotiation: schemas.NegotiationCreate, db: Session = Depends(get_db)
):
    """Initializes a new negotiation session and saves it to the database."""
    try:
        session_id = str(uuid.uuid4())
        db_negotiation = models.NegotiationSession(
            id=session_id, subject=negotiation.subject
        )
        db.add(db_negotiation)
        db.commit()
        db.refresh(db_negotiation)
        logger.info(f"Negotiation session created successfully with ID: {session_id}")
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
    status_code=status.HTTP_201_CREATED,
)
def analyze_new_message(
    negotiation_id: str,
    message: schemas.MessageCreate,
    db: Session = Depends(get_db),
    engine: NegotiationEngine = Depends(get_engine),
):
    """
    Analyzes a new message and returns a structured response including
    analysis, recommendation, simulation, and paginated history.
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

        db_message = models.Message(
            id=str(uuid.uuid4()),
            negotiation_id=negotiation_id,
            sender_id=message.sender_id,
            content=message.content,
            analysis=analysis,  # Store the full analysis object as JSONB
        )
        db.add(db_message)
        db.commit()

        history = [{"analysis": msg.analysis} for msg in db_negotiation.messages]
        recommendation = engine.recommend_tactic(history)
        simulation = engine.simulate_outcome(
            {"our_min": 5000, "our_max": 10000, "their_min": 7000, "their_max": 12000}
        )

        logger.info(f"Message in negotiation {negotiation_id} analyzed successfully.")

        return {
            "message_id": db_message.id,
            "analysis": analysis,
            "recommended_tactic": recommendation,
            "simulation": simulation,
            "history": history[-10:],
        }
    except Exception as e:
        logger.error(f"Error analyzing message for negotiation {negotiation_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while analyzing the message.",
        )


@router.get("/negotiations/{negotiation_id}", response_model=schemas.Negotiation)
def get_negotiation_history(
    negotiation_id: str,
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    """
    Fetches the full history of a negotiation session with robust pagination.
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
    db_negotiation.messages = db_negotiation.messages[skip : skip + limit]
    return db_negotiation


@router.websocket("/ws/{negotiation_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    negotiation_id: str,
    db: Session = Depends(get_db),
    engine: NegotiationEngine = Depends(get_engine),
):
    """Handles real-time negotiation chat via WebSocket."""
    await websocket.accept()

    db_negotiation = (
        db.query(models.NegotiationSession)
        .filter(models.NegotiationSession.id == negotiation_id)
        .first()
    )
    if not db_negotiation:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    try:
        while True:
            user_message = await websocket.receive_text()
            analysis = engine.analyze_message(user_message)
            db_user_message = models.Message(
                id=str(uuid.uuid4()),
                negotiation_id=negotiation_id,
                sender_id="user",
                content=user_message,
                analysis=analysis,
            )
            db.add(db_user_message)
            db.commit()

            history = [{"analysis": msg.analysis} for msg in db_negotiation.messages]
            recommendation = engine.recommend_tactic(history)
            bot_reply = recommendation["bot_response"]

            await websocket.send_json(
                {
                    "sender": "ai_negotiator",
                    "text": bot_reply,
                    "tactic": recommendation["tactic"],
                }
            )

            bot_analysis = engine.analyze_message(bot_reply)
            db_bot_message = models.Message(
                id=str(uuid.uuid4()),
                negotiation_id=negotiation_id,
                sender_id="ai_negotiator",
                content=bot_reply,
                analysis=bot_analysis,
            )
            db.add(db_bot_message)
            db.commit()
    except Exception as e:
        logger.error(f"WebSocket error for negotiation {negotiation_id}: {e}")
    finally:
        await websocket.close()
        
@router.post(
    "/negotiations",
    response_model=schemas.Negotiation,
    status_code=status.HTTP_201_CREATED,
)
def create_negotiation(
    negotiation: schemas.NegotiationCreate, db: Session = Depends(get_db)
):
    """Initializes a new negotiation session with multiple participants."""
    try:
        session_id = str(uuid.uuid4())
        db_negotiation = models.NegotiationSession(
            id=session_id, subject=negotiation.subject
        )
        db.add(db_negotiation)
        
        # Add participants to the new table
        for participant in negotiation.participants:
            db_participant = models.NegotiationParticipant(
                session_id=session_id,
                participant_id=participant.participant_id,
                participant_name=participant.participant_name,
            )
            db.add(db_participant)

        db.commit()
        db.refresh(db_negotiation)
        logger.info(f"Multi-party negotiation session created successfully with ID: {session_id}")
        return db_negotiation
    except Exception as e:
        logger.error(f"Database error while creating negotiation session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create negotiation session.",
        )