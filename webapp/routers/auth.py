from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from chimera_intel.core.database import get_db
from chimera_intel.core.user_manager import UserManager
from chimera_intel.core import schemas, models

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token") # Corrected token URL


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    user_manager = UserManager(db)
    user = user_manager.get_user_from_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(
    current_user: models.User = Depends(get_current_user),
):
    # Assuming models.User has an 'is_active' attribute.
    # If not, this check should be modified or removed.
    # if not current_user.is_active:
    #     raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def get_current_active_admin(
    current_user: models.User = Depends(get_current_active_user),
):
    if current_user.role != schemas.UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges",
        )
    return current_user


@router.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user_manager = UserManager(db)
    user = user_manager.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = user_manager.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/register", response_model=schemas.User)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    user_manager = UserManager(db)
    db_user = user_manager.get_user(user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return user_manager.create_user(user)


@router.get("/users/me", response_model=schemas.User)
async def read_users_me(current_user: models.User = Depends(get_current_active_user)):
    return current_user


@router.get("/admin/dashboard", summary="Get admin dashboard data")
async def get_admin_dashboard(
    current_admin: models.User = Depends(get_current_active_admin),
):
    """
    An example endpoint that is protected and only accessible by admin users.
    """
    return {"message": f"Welcome, Admin {current_admin.username}!"}