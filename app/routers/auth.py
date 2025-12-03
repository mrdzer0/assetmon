"""
Authentication routes
Handles login, logout
"""

from fastapi import APIRouter, Request, Depends, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime

from app.db import get_db
from app.auth import authenticate_user, create_session_token, get_optional_user
from app.session_store import create_session, delete_session
from app.models import User

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = None, success: str = None):
    """Show login page"""
    # If already logged in, redirect to dashboard
    try:
        from app.auth import get_current_user
        user = get_current_user(request, next(get_db()))
        if user:
            return RedirectResponse(url="/", status_code=302)
    except:
        pass

    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "success": success
    })


@router.post("/login")
def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Handle login form submission"""
    # Authenticate user
    user = authenticate_user(db, username, password)

    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password"
        }, status_code=401)

    # Create session token
    session_token = create_session_token()

    # Store session
    create_session(user.id, session_token)

    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    # Create redirect response
    redirect_response = RedirectResponse(url="/", status_code=302)

    # Set session cookie
    redirect_response.set_cookie(
        key="asset_monitor_session",
        value=session_token,
        httponly=True,
        max_age=480 * 60,  # 8 hours
        samesite="lax"
    )

    return redirect_response


@router.get("/logout")
def logout(request: Request, response: Response):
    """Handle logout"""
    # Get session token
    session_token = request.cookies.get("asset_monitor_session")

    # Delete session
    if session_token:
        delete_session(session_token)

    # Create redirect response
    redirect_response = RedirectResponse(url="/login?success=Successfully logged out", status_code=302)

    # Delete cookie
    redirect_response.delete_cookie(key="asset_monitor_session")

    return redirect_response
