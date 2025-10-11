from typing import Dict, Any, Optional, List
import json
import logging
from .database import get_db_connection
from .utils import console

# --- Global Cache for Cultural Profiles ---
_profile_cache: Dict[str, Dict[str, Any]] = {}

def add_cultural_profile(profile_data: Dict[str, Any]):
    """Adds or updates a cultural profile in the database and clears the cache."""
    global _profile_cache
    conn = get_db_connection()
    if not conn:
        logging.error("Cannot add cultural profile: No database connection.")
        return
    try:
        with conn.cursor() as cursor:
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
                    profile_data["country_code"].upper(),
                    profile_data["country_name"],
                    profile_data["directness"],
                    profile_data["formality"],
                    profile_data["power_distance"],
                    profile_data["individualism"],
                    profile_data["uncertainty_avoidance"],
                ),
            )
            conn.commit()
            console.print(
                f"[bold green]Successfully added/updated cultural profile for {profile_data['country_name']}.[/bold green]"
            )
            # Clear cache after an update
            _profile_cache.clear()
    except Exception as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not add cultural profile: {e}"
        )
    finally:
        if conn:
            conn.close()

def get_cultural_profile(country_code: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves a cultural profile from the cache or database.
    Caches profiles in memory to reduce database queries.
    """
    global _profile_cache
    if not country_code:
        return None
        
    # Check cache first
    if country_code.upper() in _profile_cache:
        return _profile_cache[country_code.upper()]

    conn = get_db_connection()
    if not conn:
        logging.error("Cannot retrieve cultural profile: No database connection.")
        return None
    
    profile = None
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT country_code, country_name, directness, formality, power_distance, individualism, uncertainty_avoidance FROM cultural_profiles WHERE country_code = %s",
                (country_code.upper(),),
            )
            record = cursor.fetchone()
            if record:
                profile = {
                    "country_code": record[0],
                    "country_name": record[1],
                    "directness": record[2],
                    "formality": record[3],
                    "power_distance": record[4],
                    "individualism": record[5],
                    "uncertainty_avoidance": record[6],
                }
                # Store in cache for future requests
                _profile_cache[country_code.upper()] = profile
    except Exception as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not retrieve cultural profile: {e}"
        )
    finally:
        if conn:
            conn.close()
    return profile

def populate_initial_cultural_data():
    """Adds a few example cultural profiles to the database for demonstration."""
    initial_profiles = [
        {
            "country_code": "US", "country_name": "United States", "directness": 9,
            "formality": 4, "power_distance": 40, "individualism": 91, "uncertainty_avoidance": 46,
        },
        {
            "country_code": "JP", "country_name": "Japan", "directness": 3,
            "formality": 8, "power_distance": 54, "individualism": 46, "uncertainty_avoidance": 92,
        },
        {
            "country_code": "DE", "country_name": "Germany", "directness": 8,
            "formality": 7, "power_distance": 35, "individualism": 67, "uncertainty_avoidance": 65,
        },
        {
            "country_code": "BR", "country_name": "Brazil", "directness": 6,
            "formality": 5, "power_distance": 69, "individualism": 38, "uncertainty_avoidance": 76,
        },
    ]
    console.print("[yellow]Populating initial cultural data...[/yellow]")
    for profile in initial_profiles:
        add_cultural_profile(profile)

def get_all_cultural_profiles() -> List[Dict[str, Any]]:
    """Retrieves all cultural profiles from the database."""
    conn = get_db_connection()
    if not conn:
        logging.error("Cannot retrieve cultural profiles: No database connection.")
        return []
    
    profiles = []
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT country_code, country_name, directness, formality, power_distance, individualism, uncertainty_avoidance FROM cultural_profiles ORDER BY country_name;")
            records = cursor.fetchall()
            for record in records:
                profiles.append({
                    "country_code": record[0], "country_name": record[1], "directness": record[2],
                    "formality": record[3], "power_distance": record[4], "individualism": record[5],
                    "uncertainty_avoidance": record[6],
                })
    except Exception as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not retrieve all cultural profiles: {e}"
        )
    finally:
        if conn:
            conn.close()
    return profiles