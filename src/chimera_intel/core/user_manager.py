"""Module for managing users and authentication.

Handles user creation, password hashing, authentication, and context switching
for the currently logged-in user, enabling multi-user support.
"""

import os
import typer
import logging
from typing import Optional
from passlib.context import CryptContext
from datetime import datetime, timedelta
from . import models, schemas
from jose import jwt
from .schemas import User
from .database import create_user_in_db, get_user_from_db
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

def get_user(self, username: str):
        return self.db.query(models.User).filter(models.User.username == username).first()

def create_user(self, user: schemas.UserCreate):
        hashed_password = pwd_context.hash(user.password)
        db_user = models.User(username=user.username, hashed_password=hashed_password)
        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)
        return db_user

def authenticate_user(self, username: str, password: str) -> Optional[models.User]:
        user = self.get_user(username)
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


# --- Typer CLI Application ---


user_app = typer.Typer()


@user_app.command("add")
def add_user_command(
    username: str = typer.Argument(..., help="The username for the new user."),
    password: str = typer.Option(
        ..., "--password", prompt=True, hide_input=True, help="The user's password."
    ),
):
    """Adds a new user to the Chimera Intel database."""
    if get_user_from_db(username):
        console.print(f"[bold red]Error:[/bold red] User '{username}' already exists.")
        raise typer.Exit(code=1)
    hashed_password = get_password_hash(password)
    create_user_in_db(username, hashed_password)
    console.print(f"[bold green]Successfully created user '{username}'.[/bold green]")


@user_app.command("login")
def login_command(
    username: str = typer.Argument(..., help="The username to log in with."),
):
    """Logs in a user, setting them as the active context."""
    password = typer.prompt("Password", hide_input=True)
    user = get_user_from_db(username)
    if user and verify_password(password, user.hashed_password):
        set_active_user(username)
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
