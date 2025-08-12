import os
import base64
import requests
import sqlite3
from email.mime.text import MIMEText
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv
from pydantic import BaseModel


load_dotenv()

app = FastAPI()

GMAIL_SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

DB_FILE = "tokens.db"

# Database init
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS google_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            access_token TEXT,
            refresh_token TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Save tokens to DB
def save_tokens(access_token, refresh_token):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO google_tokens (access_token, refresh_token) VALUES (?, ?)", (access_token, refresh_token))
    conn.commit()
    conn.close()

# Get latest refresh_token from DB
def get_refresh_token():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT refresh_token FROM google_tokens ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

# Get new access_token from refresh_token
def refresh_access_token(refresh_token):
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    r = requests.post(token_url, data=data)
    return r.json().get("access_token")

@app.get("/auth/google/start")
def google_oauth_start():
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        "&response_type=code"
        "&scope=https://www.googleapis.com/auth/gmail.send"
        "&access_type=offline"
        "&prompt=consent"
    )
    return RedirectResponse(auth_url)

@app.get("/auth/google/callback")
def google_oauth_callback(code: str):
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    r = requests.post(token_url, data=data)
    tokens = r.json()

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")

    if refresh_token:
        save_tokens(access_token, refresh_token)

    return {"message": "Tokens saved successfully!", "tokens": tokens}


class EmailPayload(BaseModel):
    to: str
    subject: str
    message: str

@app.post("/send-email/")
def send_email(payload: EmailPayload):
    refresh_token = get_refresh_token()
    if not refresh_token:
        return {"error": "No refresh token found"}

    access_token = refresh_access_token(refresh_token)
    mime_msg = MIMEText(payload.message)
    mime_msg["to"] = payload.to
    mime_msg["subject"] = payload.subject
    raw = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode()

    r = requests.post(
        GMAIL_SEND_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        json={"raw": raw}
    )
    return {"message": "Email sent!"} if r.status_code == 200 else {"error": r.text}