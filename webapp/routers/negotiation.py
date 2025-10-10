from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
import uuid
import json

# Core Chimera Intel imports

from chimera_intel.core.database import get_db, NegotiationModel, MessageModel
from chimera_intel.core.schemas import (
    Negotiation,
    Message,
    SimulationScenario,
    NegotiationParty,
)
from chimera_intel.core.negotiation import NegotiationEngine

router = APIRouter()
# In a production app, you might manage the engine's lifecycle differently

engine = NegotiationEngine()


@router.post("/negotiations", response_model=Negotiation)
def create_negotiation(subject: str, db: Session = Depends(get_db)):
    """Initializes a new negotiation session and saves it to the database."""
    session_id = str(uuid.uuid4())
    db_negotiation = NegotiationModel(id=session_id, subject=subject)
    db.add(db_negotiation)
    db.commit()
    db.refresh(db_negotiation)
    return db_negotiation


@router.post("/negotiations/{negotiation_id}/messages")
def analyze_new_message(
    negotiation_id: str, message: Message, db: Session = Depends(get_db)
):
    """Analyzes a new message, saves it, and returns the analysis."""
    db_negotiation = (
        db.query(NegotiationModel).filter(NegotiationModel.id == negotiation_id).first()
    )
    if not db_negotiation:
        raise HTTPException(status_code=404, detail="Negotiation not found")
    analysis = engine.analyze_message(message.content)

    db_message = MessageModel(
        id=str(uuid.uuid4()),
        negotiation_id=negotiation_id,
        sender_id=message.sender_id,
        content=message.content,
        analysis=json.dumps(analysis),  # Store analysis as a JSON string
    )
    db.add(db_message)
    db.commit()

    return {"message": "Message analyzed and saved", "analysis": analysis}


@router.get("/negotiations/{negotiation_id}/recommendation")
def get_recommendation(negotiation_id: str, db: Session = Depends(get_db)):
    """Gets a strategic recommendation based on the full negotiation history."""
    db_negotiation = (
        db.query(NegotiationModel).filter(NegotiationModel.id == negotiation_id).first()
    )
    if not db_negotiation:
        raise HTTPException(status_code=404, detail="Negotiation not found")
    # Fetch the full history from the database

    history = [
        {"analysis": json.loads(msg.analysis)} for msg in db_negotiation.messages
    ]
    if not history:
        raise HTTPException(
            status_code=404, detail="No messages in this negotiation yet."
        )
    recommendation = engine.recommend_tactic(history)
    return recommendation


@router.post("/negotiations/{negotiation_id}/simulate", response_model=dict)
def run_simulation(negotiation_id: str, scenario: SimulationScenario):
    """Runs a Monte Carlo simulation for a given scenario."""
    # This endpoint could be extended to use historical data from the DB

    result = engine.simulate_outcome(scenario.dict())
    return result
