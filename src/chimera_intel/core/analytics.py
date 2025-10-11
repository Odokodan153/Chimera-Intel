import psycopg2
import json
from typing import Dict, Any, List, Optional
import matplotlib.pyplot as plt
import pandas as pd
import typer

analytics_app = typer.Typer()


def get_negotiation_kpis(db_params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates and returns a dictionary of Key Performance Indicators (KPIs)
    for negotiation performance.
    """
    conn = psycopg2.connect(**db_params)
    if not conn:
        return {"error": "Could not connect to the database."}
    kpis = {}
    try:
        with conn.cursor() as cursor:
            # --- Success Rate ---

            cursor.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE analysis->>'intent' = 'acceptance') * 100.0 / COUNT(*)
                FROM messages
                WHERE analysis->>'intent' IN ('acceptance', 'rejection');
            """
            )
            success_rate = cursor.fetchone()[0]
            kpis["success_rate"] = round(success_rate, 2) if success_rate else 0

            # --- Average Deal Value ---

            cursor.execute(
                """
                SELECT AVG((analysis->>'offer_amount')::float)
                FROM messages
                WHERE analysis->>'intent' = 'acceptance';
            """
            )
            avg_deal_value = cursor.fetchone()[0]
            kpis["average_deal_value"] = (
                round(avg_deal_value, 2) if avg_deal_value else 0
            )

            # --- Average Negotiation Length ---

            cursor.execute(
                """
                SELECT AVG(turn_count) FROM (
                    SELECT negotiation_id, COUNT(*) as turn_count
                    FROM messages
                    GROUP BY negotiation_id
                ) as negotiation_lengths;
            """
            )
            avg_length = cursor.fetchone()[0]
            kpis["average_negotiation_length"] = (
                round(avg_length, 2) if avg_length else 0
            )
    except Exception as e:
        kpis["error"] = f"An error occurred while calculating KPIs: {e}"
    finally:
        if conn:
            conn.close()
    return kpis


@analytics_app.command("plot-sentiment")
def plot_sentiment_trajectory(
    negotiation_id: str = typer.Argument(
        ..., help="The ID of the negotiation to plot."
    ),
    output_path: Optional[str] = typer.Option(
        None, "--output", "-o", help="Path to save the plot image."
    ),
):
    """
    Retrieves the sentiment scores for a given negotiation and plots them over time.
    """
    from .config_loader import API_KEYS

    db_params = {
        "dbname": getattr(API_KEYS, "db_name", None),
        "user": getattr(API_KEYS, "db_user", None),
        "password": getattr(API_KEYS, "db_password", None),
        "host": getattr(API_KEYS, "db_host", None),
    }
    conn = psycopg2.connect(**db_params)
    if not conn:
        print("Error: Could not connect to the database.")
        return
    try:
        query = """
            SELECT
                timestamp,
                (analysis->>'tone_score')::float as sentiment
            FROM messages
            WHERE negotiation_id = %s
            ORDER BY timestamp;
        """
        df = pd.read_sql_query(query, conn, params=(negotiation_id,))

        if df.empty:
            print(f"No messages found for negotiation ID: {negotiation_id}")
            return
        plt.figure(figsize=(12, 6))
        plt.plot(df["timestamp"], df["sentiment"], marker="o", linestyle="-")

        plt.title(f"Sentiment Trajectory for Negotiation: {negotiation_id}")
        plt.xlabel("Time")
        plt.ylabel("Sentiment Score (-1 to 1)")
        plt.grid(True)
        plt.ylim(-1.1, 1.1)

        plt.gcf().autofmt_xdate()

        if output_path:
            plt.savefig(output_path)
            print(f"Plot saved to {output_path}")
        else:
            plt.show()
    except Exception as e:
        print(f"An error occurred while plotting sentiment trajectory: {e}")
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    analytics_app()
