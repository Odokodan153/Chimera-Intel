from typing import Dict, Any, Optional
from .database import get_db_connection
from .utils import console


def add_cultural_profile(profile_data: Dict[str, Any]):
    """Adds or updates a cultural profile in the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO cultural_profiles (country_code, country_name, directness, formality, power_distance, individualism, uncertainty_avoidance)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (country_code) DO UPDATE SET
                country_name = EXCLUDED.country_name,
                directness = EXCLUDED.directness,
                formality = EXCLUDED.formality,
                power_distance = EXCLUDED.power_distance,
                individualism = EXCLUDED.individualism,
                uncertainty_avoidance = EXCLUDED.uncertainty_avoidance;
            """,
            (
                profile_data["country_code"],
                profile_data["country_name"],
                profile_data["directness"],
                profile_data["formality"],
                profile_data["power_distance"],
                profile_data["individualism"],
                profile_data["uncertainty_avoidance"],
            ),
        )
        conn.commit()
        cursor.close()
        conn.close()
        console.print(
            f"[bold green]Successfully added/updated cultural profile for {profile_data['country_name']}.[/bold green]"
        )
    except Exception as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not add cultural profile: {e}"
        )


def get_cultural_profile(country_code: str) -> Optional[Dict[str, Any]]:
    """Retrieves a cultural profile from the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM cultural_profiles WHERE country_code = %s",
            (country_code.upper(),),
        )
        record = cursor.fetchone()
        if record:
            return {
                "country_code": record[0],
                "country_name": record[1],
                "directness": record[2],
                "formality": record[3],
                "power_distance": record[4],
                "individualism": record[5],
                "uncertainty_avoidance": record[6],
            }
        return None
    except Exception as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not retrieve cultural profile: {e}"
        )
        return None


def populate_initial_cultural_data():
    """Adds a few example cultural profiles to the database."""
    initial_profiles = [
        {
            "country_code": "US",
            "country_name": "United States",
            "directness": 9,
            "formality": 4,
            "power_distance": 40,
            "individualism": 91,
            "uncertainty_avoidance": 46,
        },
        {
            "country_code": "JP",
            "country_name": "Japan",
            "directness": 3,
            "formality": 8,
            "power_distance": 54,
            "individualism": 46,
            "uncertainty_avoidance": 92,
        },
        {
            "country_code": "DE",
            "country_name": "Germany",
            "directness": 8,
            "formality": 7,
            "power_distance": 35,
            "individualism": 67,
            "uncertainty_avoidance": 65,
        },
    ]
    for profile in initial_profiles:
        add_cultural_profile(profile)
