from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Query,
    WebSocket,
    WebSocketDisconnect,
)
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from typing import List, Dict, Any
import uuid
import logging
from functools import lru_cache

# Core Chimera Intel imports

from chimera_intel.core.database import get_db
from chimera_intel.core import schemas, models
from chimera_intel.core.negotiation import NegotiationEngine
from chimera_intel.core.config_loader import CONFIG
from .auth import get_current_user

# Configure structured logging

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
    model_path = CONFIG.modules.negotiation.model_path
    try:
        # Attempt to load a potentially fine-tuned transformer model

        return NegotiationEngine(model_path=model_path)
    except Exception as e:
        logger.error(f"FATAL: Could not load transformer model at {model_path}: {e}")
        logger.warning(
            "Resilience Alert: Falling back to the placeholder Naive Bayes model."
        )
        # Fallback to the simpler, non-model-dependent engine

        return NegotiationEngine()


router = APIRouter()


@router.post(
    "/negotiations",
    response_model=schemas.Negotiation,
    status_code=status.HTTP_201_CREATED,
)
def create_negotiation(
    negotiation: schemas.NegotiationCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
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
        logger.info(
            f"Multi-party negotiation session created successfully with ID: {session_id}"
        )
        return db_negotiation
    except IntegrityError as e:
        db.rollback()
        logger.error(
            f"Database integrity error while creating negotiation session: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A negotiation session with the same identifier already exists.",
        )
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error while creating negotiation session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create negotiation session due to a database error.",
        )
    except Exception as e:
        db.rollback()
        logger.error(f"An unexpected error occurred: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred.",
        )


@router.post("/negotiations/{negotiation_id}/join", status_code=status.HTTP_200_OK)
def join_negotiation(
    negotiation_id: str,
    participant: schemas.NegotiationParticipantCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Adds a participant to a negotiation session."""
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
    db_participant = models.NegotiationParticipant(
        session_id=negotiation_id,
        participant_id=participant.participant_id,
        participant_name=participant.participant_name,
    )
    db.add(db_participant)
    db.commit()
    return {"message": "Participant added to the negotiation session."}


@router.post("/negotiations/{negotiation_id}/leave", status_code=status.HTTP_200_OK)
def leave_negotiation(
    negotiation_id: str,
    participant: schemas.NegotiationParticipantCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Removes a participant from a negotiation session."""
    db_participant = (
        db.query(models.NegotiationParticipant)
        .filter(
            models.NegotiationParticipant.session_id == negotiation_id,
            models.NegotiationParticipant.participant_id == participant.participant_id,
        )
        .first()
    )
    if not db_participant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Participant not found in the negotiation session.",
        )
    db.delete(db_participant)
    db.commit()
    return {"message": "Participant removed from the negotiation session."}


@router.post(
    "/negotiations/{negotiation_id}/messages",
    response_model=schemas.AnalysisResponse,
)
def analyze_new_message(
    negotiation_id: str,
    message: schemas.MessageCreate,
    simulation_scenario: Dict[str, int],
    db: Session = Depends(get_db),
    engine: NegotiationEngine = Depends(get_engine),
    current_user: models.User = Depends(get_current_user),
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

        db_message = models.Message(
            id=str(uuid.uuid4()),
            negotiation_id=negotiation_id,
            sender_id=message.sender_id,
            content=message.content,
            analysis=analysis,
        )
        db.add(db_message)
        db.commit()

        # Fetch recent messages to provide context for the recommendation

        recent_messages = (
            db.query(models.Message)
            .filter(models.Message.negotiation_id == negotiation_id)
            .order_by(models.Message.timestamp.desc())
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
        simulation = engine.simulate_outcome(simulation_scenario)
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
def get_negotiation_history(
    negotiation_id: str,
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: models.User = Depends(get_current_user),
):
    """
    Fetches the full history of a negotiation session with robust pagination.
    """
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
):
    """Handles real-time negotiation chat via WebSocket."""
    db: Session = next(get_db())
    user = await get_current_user(token, db)
    if not user:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await websocket.accept()

    engine: NegotiationEngine = get_engine()

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

            # Save user message

            db_user_message = models.Message(
                id=str(uuid.uuid4()),
                negotiation_id=negotiation_id,
                sender_id="user",
                content=user_message,
                analysis=analysis,
            )
            db.add(db_user_message)
            db.commit()

            # Generate and send bot reply

            history = [
                {
                    "sender_id": msg.sender_id,
                    "content": msg.content,
                    "analysis": msg.analysis,
                }
                for msg in db_negotiation.messages
            ]
            recommendation = await engine.recommend_tactic_async(history)
            bot_reply = recommendation.get(
                "bot_response", "I'm not sure how to respond to that."
            )

            await websocket.send_json(
                {
                    "sender": "ai_negotiator",
                    "text": bot_reply,
                    "tactic": recommendation.get("tactic", "Unknown"),
                }
            )

            # Save bot message

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
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for negotiation {negotiation_id}")
    except Exception as e:
        logger.error(f"WebSocket error for negotiation {negotiation_id}: {e}")
    finally:
        db.close()
        logger.info(f"Closed DB session for WebSocket negotiation {negotiation_id}")
