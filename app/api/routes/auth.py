from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from google_auth_oauthlib.flow import Flow
from app.core.config import settings
from app.core.security import create_access_token
import requests
import os

router = APIRouter()

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

@router.get("/google/login")
def login():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [settings.GOOGLE_REDIRECT_URI]
            }
        },
        scopes=["openid", "email", "profile"]
    )
    flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
    auth_url, _ = flow.authorization_url(prompt="consent")
    return RedirectResponse(auth_url)

@router.get("/google/callback")
def callback(request: Request):
    try:
        code = request.query_params["code"]
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [settings.GOOGLE_REDIRECT_URI]
                }
            },
            scopes=["openid", "email", "profile"]
        )
        flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
        flow.fetch_token(code=code)

        credentials = flow.credentials
        session = requests.Session()
        session.headers.update({"Authorization": f"Bearer {credentials.token}"})
        userinfo = session.get("https://www.googleapis.com/oauth2/v2/userinfo").json()

        email = userinfo.get("email")
        name = userinfo.get("name")

        if not email:
            raise HTTPException(status_code=400, detail="Google login failed")

        token = create_access_token({"sub": email, "name": name})

        redirect_url = f"{settings.FRONTEND_URL}/login/success?token={token}&name={name}"
        return RedirectResponse(redirect_url)

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
