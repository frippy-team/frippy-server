from fastapi import APIRouter, Request, HTTPException, Body
from fastapi.responses import RedirectResponse, JSONResponse
from google_auth_oauthlib.flow import Flow
from app.core.config import settings
from app.core.security import create_access_token
import os, requests, traceback

router = APIRouter()

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid",
]

@router.get("/google/login")
def login():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [settings.GOOGLE_REDIRECT_URI],
            }
        },
        scopes=GOOGLE_SCOPES,
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
                    "redirect_uris": [settings.GOOGLE_REDIRECT_URI],
                }
            },
            scopes=GOOGLE_SCOPES,
        )
        flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
        flow.fetch_token(code=code)

        credentials = flow.credentials
        session = requests.Session()
        session.headers.update({"Authorization": f"Bearer {credentials.token}"})
        userinfo = session.get("https://www.googleapis.com/oauth2/v2/userinfo").json()

        email = userinfo.get("email")
        name = userinfo.get("name")
        picture = userinfo.get("picture")

        if not email or not userinfo.get("verified_email", False):
            raise HTTPException(status_code=400, detail="Google login failed: Email not verified")

        token = create_access_token({
            "sub": email,
            "name": name,
            "picture": picture,
            "provider": "google",
        })

        redirect_url = f"{settings.CLIENT_URL}/login/success?token={token}"
        return RedirectResponse(redirect_url)

    except Exception as e:
        print("OAuth CallBack Error:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Error occurred while processing OAuth")

@router.post("/register")
def register_user(
    user_data: dict = Body(...)
):
    """
    user_data: {
        "email": str,
        "name": str,
        "picture": str,
        "provider": "google",
        "phone_number": str
    }
    """
    # ⚠️ 예시 코드. 실제 DB 연동 필요
    email = user_data["email"]
    provider = user_data["provider"]
    phone = user_data["phone_number"]

    # 👉 여기에 DB에서 email로 유저 찾기/없으면 생성
    # 👉 소셜 계정 연결 여부 확인
    # 👉 phone_number로 중복 여부 검사 등 추가

    print(f"[회원가입 요청] email={email}, provider={provider}, phone={phone}")
    
    token = create_access_token({"sub": email})
    return JSONResponse({
        "message": "User registered/connected",
        "access_token": token,
    })
