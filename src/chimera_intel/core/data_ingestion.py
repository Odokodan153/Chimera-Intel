import uuid
import json
from .database import get_db_connection
from .schemas import Counterparty, BehavioralProfile, MarketIndicator
from .utils import console


def add_counterparty(counterparty: Counterparty) -> str:
    """Adds a new counterparty to the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        counterparty_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO counterparties (id, name, industry, country, notes) VALUES (%s, %s, %s, %s, %s)",
            (
                counterparty_id,
                counterparty.name,
                counterparty.industry,
                counterparty.country,
                "",
            ),
        )
        conn.commit()
        cursor.close()
        conn.close()
        return counterparty_id
    except Exception as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not add counterparty: {e}"
        )
        return ""


def add_behavioral_profile(profile: BehavioralProfile) -> str:
    """Adds a behavioral profile for a counterparty."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        profile_id = str(uuid.uuid4())
        motivators = json.dumps(profile.key_motivators)
        cursor.execute(
            "INSERT INTO behavioral_profiles (id, counterparty_id, communication_style, risk_appetite, key_motivators) VALUES (%s, %s, %s, %s, %s)",
            (
                profile_id,
                profile.party_id,
                profile.communication_style,
                profile.risk_appetite,
                motivators,
            ),
        )
        conn.commit()
        cursor.close()
        conn.close()
        return profile_id
    except Exception as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not add behavioral profile: {e}"
        )
        return ""


def add_market_indicator(indicator: MarketIndicator) -> str:
    """Adds a new market indicator to the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        indicator_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO market_indicators (id, name, value, source) VALUES (%s, %s, %s, %s)",
            (indicator_id, indicator.name, indicator.value, indicator.source),
        )
        conn.commit()
        cursor.close()
        conn.close()
        return indicator_id
    except Exception as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not add market indicator: {e}"
        )
        return ""
