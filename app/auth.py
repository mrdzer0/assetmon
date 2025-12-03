"""
Authentication utilities
Handles password hashing, verification, and session management
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import User

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Basic Auth (for API if needed)
security = HTTPBasic()

# Session configuration
SESSION_COOKIE_NAME = "asset_monitor_session"
SESSION_TIMEOUT_MINUTES = 480  # 8 hours


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt

    Args:
        password: Plain text password

    Returns:
        Hashed password
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash

    Args:
        plain_password: Plain text password to verify
        hashed_password: Hashed password to check against

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """
    Authenticate a user with username and password

    Args:
        db: Database session
        username: Username
        password: Plain text password

    Returns:
        User object if authentication successful, None otherwise
    """
    user = db.query(User).filter(User.username == username).first()

    if not user:
        return None

    if not user.is_active:
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user


def create_session_token() -> str:
    """
    Create a secure random session token

    Returns:
        Hex-encoded random token
    """
    return secrets.token_hex(32)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """
    Get currently authenticated user from session

    Args:
        request: FastAPI request object
        db: Database session

    Returns:
        User object

    Raises:
        HTTPException: If not authenticated
    """
    # Check for session cookie
    session_token = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # For simplicity, we'll store session_token in a simple dict
    # In production, use Redis or database
    from app.session_store import get_user_from_session

    user_id = get_user_from_session(session_token)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == user_id).first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user


def get_optional_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """
    Get current user if authenticated, None otherwise
    (Does not raise exception if not authenticated)

    Args:
        request: FastAPI request object
        db: Database session

    Returns:
        User object or None
    """
    try:
        return get_current_user(request, db)
    except HTTPException:
        return None


def require_superuser(current_user: User = Depends(get_current_user)) -> User:
    """
    Require that the current user is a superuser

    Args:
        current_user: Current authenticated user

    Returns:
        User object

    Raises:
        HTTPException: If user is not a superuser
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required"
        )

    return current_user
