import psycopg2
from typing import Dict, Any, List, Optional
from .utils import console


def get_db_connection(
    db_params: Dict[str, Any],
) -> Optional[psycopg2.extensions.connection]:
    """Establishes a connection to the PostgreSQL database."""
    try:
        return psycopg2.connect(**db_params)
    except psycopg2.OperationalError as e:
        console.print(f"[bold red]Database Connection Error:[/bold red] {e}")
        return None


def get_negotiation_kpis(db_params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates Key Performance Indicators (KPIs) across all negotiation sessions.
    """
    conn = get_db_connection(db_params)
    if not conn:
        return {}
    kpis = {
        "total_sessions": 0,
        "successful_deals": 0,
        "average_duration_hours": 0,
        "sentiment_trend": [],
    }

    try:
        cursor = conn.cursor()

        # Total sessions

        cursor.execute("SELECT COUNT(*) FROM negotiation_sessions;")
        kpis["total_sessions"] = cursor.fetchone()[0]

        # Successful deals (assuming 'closed' status means success)

        cursor.execute(
            "SELECT COUNT(*) FROM negotiation_sessions WHERE status = 'closed';"
        )
        kpis["successful_deals"] = cursor.fetchone()[0]

        # Average duration

        cursor.execute(
            "SELECT AVG(EXTRACT(EPOCH FROM (end_time - start_time))/3600) FROM negotiation_sessions WHERE end_time IS NOT NULL;"
        )
        avg_duration = cursor.fetchone()[0]
        kpis["average_duration_hours"] = round(avg_duration, 2) if avg_duration else 0

        # Sentiment trend over time

        cursor.execute(
            """
            SELECT timestamp, analysis->>'tone_score' 
            FROM messages 
            WHERE analysis->>'tone_score' IS NOT NULL
            ORDER BY timestamp 
            LIMIT 100;
        """
        )
        sentiment_data = cursor.fetchall()
        kpis["sentiment_trend"] = [
            (row[0].isoformat(), float(row[1])) for row in sentiment_data
        ]

        cursor.close()
        return kpis
    except Exception as e:
        console.print(f"[bold red]Analytics Error:[/bold red] {e}")
        return {}
    finally:
        if conn:
            conn.close()
