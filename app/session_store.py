"""
Simple in-memory session store
In production, use Redis or database
"""

from datetime import datetime, timedelta
from typing import Optional, Dict
import threading

# Simple in-memory session store
# Format: {session_token: {"user_id": int, "expires_at": datetime}}
_sessions: Dict[str, dict] = {}
_lock = threading.Lock()

SESSION_TIMEOUT_MINUTES = 480  # 8 hours


def create_session(user_id: int, session_token: str) -> None:
    """
    Create a new session

    Args:
        user_id: User ID
        session_token: Session token
    """
    with _lock:
        _sessions[session_token] = {
            "user_id": user_id,
            "expires_at": datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        }


def get_user_from_session(session_token: str) -> Optional[int]:
    """
    Get user ID from session token

    Args:
        session_token: Session token

    Returns:
        User ID if session is valid, None otherwise
    """
    with _lock:
        session = _sessions.get(session_token)

        if not session:
            return None

        # Check if session expired
        if datetime.utcnow() > session["expires_at"]:
            # Clean up expired session
            del _sessions[session_token]
            return None

        # Extend session on activity
        session["expires_at"] = datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)

        return session["user_id"]


def delete_session(session_token: str) -> None:
    """
    Delete a session (logout)

    Args:
        session_token: Session token
    """
    with _lock:
        if session_token in _sessions:
            del _sessions[session_token]


def cleanup_expired_sessions() -> int:
    """
    Clean up all expired sessions

    Returns:
        Number of sessions cleaned up
    """
    with _lock:
        now = datetime.utcnow()
        expired = [
            token for token, session in _sessions.items()
            if now > session["expires_at"]
        ]

        for token in expired:
            del _sessions[token]

        return len(expired)


def get_active_sessions_count() -> int:
    """
    Get count of active sessions

    Returns:
        Number of active sessions
    """
    cleanup_expired_sessions()
    with _lock:
        return len(_sessions)
