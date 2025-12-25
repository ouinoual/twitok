import os
import uuid
import secrets
import subprocess
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI()

FILES_DIR = "files"
os.makedirs(FILES_DIR, exist_ok=True)
app.mount("/files", StaticFiles(directory=FILES_DIR), name="files")

PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL")

TIKTOK_CLIENT_KEY = os.environ.get("TIKTOK_CLIENT_KEY")
TIKTOK_CLIENT_SECRET = os.environ.get("TIKTOK_CLIENT_SECRET")
TIKTOK_REDIRECT_URI = os.environ.get("TIKTOK_REDIRECT_URI")

DEFAULT_SCOPE = "user.info.basic,video.upload"


def _require_env(value: str | None, name: str):
    if not value:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/extract")
def extract(payload: dict):
    url = payload.get("url")
    if not url:
        return JSONResponse({"error": "Missing url"}, status_code=400)

    file_id = str(uuid.uuid4())
    outtmpl = os.path.join(FILES_DIR, f"{file_id}.%(ext)s")

    cmd = [
        "yt-dlp",
        "-f", "bv*+ba/best",
        "--merge-output-format", "mp4",
        "-o", outtmpl,
        url,
    ]

    subprocess.check_call(cmd)

    if not PUBLIC_BASE_URL:
        return JSONResponse({"error": "Missing PUBLIC_BASE_URL"}, status_code=500)

    return {"fileUrl": f"{PUBLIC_BASE_URL}/files/{file_id}.mp4"}


@app.get("/tiktok/login")
def tiktok_login():
    client_key = _require_env(TIKTOK_CLIENT_KEY, "TIKTOK_CLIENT_KEY")
    redirect_uri = _require_env(TIKTOK_REDIRECT_URI, "TIKTOK_REDIRECT_URI")

    state = secrets.token_urlsafe(16)

    params = {
        "client_key": client_key,
        "scope": DEFAULT_SCOPE,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "state": state,
    }

    auth_url = "https://www.tiktok.com/v2/auth/authorize/?" + urlencode(params)
    return RedirectResponse(auth_url)


@app.get("/tiktok/callback")
async def tiktok_callback(code: str | None = None, state: str | None = None, error: str | None = None):
    if error:
        return JSONResponse({"ok": False, "error": error, "state": state}, status_code=400)
    if not code:
        return JSONResponse({"ok": False, "error": "Missing code", "state": state}, status_code=400)

    client_key = _require_env(TIKTOK_CLIENT_KEY, "TIKTOK_CLIENT_KEY")
    client_secret = _require_env(TIKTOK_CLIENT_SECRET, "TIKTOK_CLIENT_SECRET")
    redirect_uri = _require_env(TIKTOK_REDIRECT_URI, "TIKTOK_REDIRECT_URI")

    data = {
        "client_key": client_key,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://open.tiktokapis.com/v2/oauth/token/",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    return JSONResponse({"ok": True, "state": state, "token_response": r.json()}, status_code=r.status_code)
