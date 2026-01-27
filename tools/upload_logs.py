import json
import os
import requests
from datetime import datetime

PORTFOLIO_OWNER = "danielmichael20208"
PORTFOLIO_REPO = "portfolio"
PORTFOLIO_PATH = "data/logs_web.json"

LOG_FILE = os.path.join(os.path.dirname(__file__), "../data/logs_web.json")

TOKEN = os.getenv("GITHUB_TOKEN")

def upload_logs(mode="auto"):
    """
    mode = "auto" → upload silently (tools call this)
    mode = "manual" → verbose output for user pipeline
    mode = "pipeline" → batch run after multiple tools
    """

    if not TOKEN:
        raise SystemExit("ERROR: GITHUB_TOKEN not set. Export it first.")

    if not os.path.exists(LOG_FILE):
        if mode != "auto":
            print("No logs to upload.")
        return

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        data = f.read()

    url = f"https://api.github.com/repos/{PORTFOLIO_OWNER}/{PORTFOLIO_REPO}/contents/{PORTFOLIO_PATH}"
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    # get latest SHA (required by GitHub)
    r = requests.get(url, headers=headers)
    sha = r.json()["sha"] if r.status_code == 200 else None

    payload = {
        "message": f"SIEM log sync {datetime.utcnow().isoformat(timespec='seconds')}Z",
        "content": data.encode("utf-8").decode("ascii"),
        "sha": sha
    }

    r = requests.put(url, json=payload, headers=headers)

    if r.status_code in (200, 201):
        if mode != "auto":
            print("[OK] Logs uploaded → GitHub Pages will redeploy.")
    else:
        print("[ERROR] Upload failed:", r.text)

def clear_local_logs():
    """optional helper for pipeline mode"""
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
        print("[OK] Local logs cleared.")
