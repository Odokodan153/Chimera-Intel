"""Module for managing users and authentication.

Handles user creation, password hashing, authentication, and context switching
for the currently logged-in user, enabling multi-user support.
"""

import os
import typer
import logging
from typing import Optional, Any, Dict
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone # Import timezone
from . import schemas
from jose import jwt
from .schemas import User

# --- MODIFIED IMPORTS ---
from .database import (
    create_user_in_db, 
    get_user_from_db, 
    update_user_fields_in_db # Import the new update function
)
from .utils import console

logger = logging.getLogger(__name__)

USER_CONTEXT_FILE = ".chimera_user_context"
SECRET_KEY = "a_very_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def get_password_hash(password: str) -> str:
    """Hashes a password using Argon2 (no 72-byte limit)."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed one."""
    return pwd_context.verify(plain_password, hashed_password)


def set_active_user(username: str) -> None:
    """Sets the currently logged-in user by writing to the context file."""
    try:
        with open(USER_CONTEXT_FILE, "w") as f:
            f.write(username)
        logger.info(f"Set active user context to '{username}'.")
    except Exception as e:
        logger.error(f"Failed to set user context: {e}")


def get_active_user() -> Optional[User]:
    """Gets the database record for the currently logged-in user."""
    if not os.path.exists(USER_CONTEXT_FILE):
        return None
    try:
        with open(USER_CONTEXT_FILE, "r") as f:
            username = f.read().strip()
        return get_user_from_db(username)
    except Exception as e:
        logger.error(f"Could not load active user: {e}")
        return None


def logout_user() -> None:
    """Logs out the current user by deleting the context file."""
    if os.path.exists(USER_CONTEXT_FILE):
        os.remove(USER_CONTEXT_FILE)
    logger.info("User logged out.")

# --- NEW FUNCTION ---
def get_user_by_username(username: str) -> Optional[User]:
    """Alias for get_user_from_db for consistency."""
    return get_user_from_db(username)

# --- NEW FUNCTION ---
def update_user_data(username: str, data: Dict[str, Any], db: Any = None) -> None:
    """
    Updates one or more fields for a user.
    Can participate in an existing transaction if `db` (conn or cursor) is passed.
    """
    import psycopg2 # Import for this function
    
    # This logic allows the function to be used standalone or in a transaction
    conn = None
    cursor = None
    try:
        if db:
            # Use the passed connection or cursor
            update_user_fields_in_db(username, data, db)
        else:
            # Create a new connection
            from .database import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            update_user_fields_in_db(username, data, cursor)
            conn.commit()
            
    except (Exception, psycopg2.Error) as e:
        if conn: # Rollback if we made a local connection
            conn.rollback()
        logger.error(f"Failed to update user {username}: {e}")
        raise # Re-raise the exception
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def create_user(self, user: schemas.UserCreate):
    # This is part of a class-based structure not used by the CLI.
    # We will ignore it for now as the CLI uses create_user_in_db
    hashed_password = pwd_context.hash(user.password)
    # ... implementation ...
    pass


def authenticate_user(username: str, password: str) -> Optional[User]:
    """Authenticates a user against the database."""
    user = get_user_from_db(username)
    if not user or not pwd_context.verify(password, user.hashed_password):
        return None
    return user


def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def update_user_field(username: str, field: str, value: Any) -> bool:
    """
    Updates a specific field for a user in the database.
    This is now implemented via update_user_data.
    """
    try:
        update_user_data(username, {field: value})
        return True
    except Exception as e:
        logger.error(f"Failed to update user {username}: {e}")
        return False


# --- Typer CLI Application ---


user_app = typer.Typer()


@user_app.command("add")
def add_user_command(
    username: str = typer.Argument(..., help="The username for the new user."),
    email: str = typer.Argument(..., help="The email for the new user."),
    password: str = typer.Option(
        ..., "--password", prompt=True, hide_input=True, help="The user's password."
    ),
):
    """Adds a new user to the Chimera Intel database."""
    if get_user_from_db(username):
        console.print(f"[bold red]Error:[/bold red] User '{username}' already exists.")
        raise typer.Exit(code=1)
    hashed_password = get_password_hash(password)
    create_user_in_db(username, email, hashed_password)
    console.print(f"[bold green]Successfully created user '{username}'.[/bold green]")


@user_app.command("login")
def login_command(
    username: str = typer.Argument(..., help="The username to log in with."),
):
    """Logs in a user, setting them as the active context and updating last_login."""
    password = typer.prompt("Password", hide_input=True)
    
    # Use the corrected authenticate_user function
    user = authenticate_user(username, password) 
    
    if user:
        set_active_user(username)
        
        # --- MODIFIED ---
        # Update the last_login timestamp
        try:
            update_user_data(username, {"last_login": datetime.now(timezone.utc)})
            logger.info(f"Updated last_login for user '{username}'.")
        except Exception as e:
            logger.error(f"Failed to update last_login for user '{username}': {e}")
            # Don't fail the login, just log the error
        
        console.print(
            f"[bold green]Successfully logged in as '{username}'.[/bold green]"
        )
    else:
        console.print("[bold red]Error:[/bold red] Invalid username or password.")
        raise typer.Exit(code=1)


@user_app.command("logout")
def logout_command():
    """Logs out the current active user."""
    logout_user()
    console.print("[bold green]Successfully logged out.[/bold green]")


@user_app.command("status")
def status_command():
    """Shows the currently logged-in user."""
    user = get_active_user()
    if user:
        console.print(f"Logged in as: [bold cyan]{user.username}[/bold cyan]")
    else:
        console.print("Not logged in.")