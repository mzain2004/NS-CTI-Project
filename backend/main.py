"""NS-CTI backend entry point."""
import os
import requests
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning
import urllib3

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import analyze, virustotal, cowrie, wazuh, pfsense, reports

# Suppress SSL warnings for Wazuh self-signed cert
urllib3.disable_warnings(InsecureRequestWarning)

load_dotenv(Path(__file__).resolve().parent / '.env')

app = FastAPI(
    title="NS-CTI API",
    description="Malware Analysis & Threat Intelligence Platform API",
    version="0.1.0",
)

# ── CORS ──────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://165.232.174.172",
        "http://165.232.174.172:80",
        "http://165.232.174.172:3000",
        "http://localhost:3000",
        "http://localhost",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────
app.include_router(analyze.router,     prefix="/api")
app.include_router(virustotal.router,  prefix="/api")
app.include_router(cowrie.router,      prefix="/api")
app.include_router(wazuh.router,       prefix="/api")
app.include_router(pfsense.router,     prefix="/api")
app.include_router(reports.router,     prefix="/api")

# ── Active-Defense Webhook ──────────────────────────────────────────────
import httpx
import logging
from fastapi import Request, BackgroundTasks

logger = logging.getLogger("autoshield-webhook")

async def get_vt_score(client: httpx.AsyncClient, resource: str, is_file: bool = True) -> int:
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_api_key:
        return 0
    type_path = "files" if is_file else "ip_addresses"
    url = f"https://www.virustotal.com/api/v3/{type_path}/{resource}"
    headers = {"x-apikey": vt_api_key}
    try:
        response = await client.get(url, headers=headers)
        if response.status_code == 200:
            attributes = response.json().get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            return stats.get("malicious", 0)
    except Exception as e:
        logger.error(f"VT API Error in webhook: {e}")
    return 0

async def send_discord_alert(client: httpx.AsyncClient, ip: str, score: int, sha256: str | None = None):
    discord_url = os.getenv("DISCORD_WEBHOOK_URL")
    if not discord_url or discord_url == "YOUR_DISCORD_WEBHOOK_URL":
        logger.warning("Discord webhook URL not configured.")
        return
    payload = {
        "embeds": [{
            "title": "🛡️ AutoShield: Threat Detected",
            "color": 15158332, # Red
            "fields": [
                {"name": "Attacker IP", "value": f"`{ip}`", "inline": True},
                {"name": "VT Malicious Score", "value": f"`{score}`", "inline": True},
                {"name": "File Hash (SHA256)", "value": f"`{sha256 or 'N/A'}`", "inline": False}
            ],
            "footer": {"text": "Autonomous Defense System"}
        }]
    }
    try:
        await client.post(discord_url, json=payload)
    except Exception as e:
        logger.error(f"Failed to send Discord alert: {e}")

async def process_webhook_alert(alert: dict):
    data = alert.get("data", {})
    ip = data.get("srcip") or data.get("src_ip")
    sha256 = data.get("sha256")
    
    if not ip:
        logger.info("No IP address in Wazuh alert, skipping active response")
        return

    logger.info(f"Processing threat webhook for IP: {ip}, SHA256: {sha256}")
    
    async with httpx.AsyncClient() as client:
        score = 0
        if sha256:
            score = await get_vt_score(client, sha256, is_file=True)
        else:
            score = await get_vt_score(client, ip, is_file=False)
        
        if score >= 3:
            logger.info(f"High threat detected in webhook! Score: {score}. Sending alert.")
            await send_discord_alert(client, ip, score, sha256)

@app.post("/webhook")
async def handle_wazuh_webhook(request: Request, background_tasks: BackgroundTasks):
    try:
        alert = await request.json()
        background_tasks.add_task(process_webhook_alert, alert)
        return {"message": "Alert accepted for processing"}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/health")
async def health():
    """Comprehensive health check endpoint."""
    
    # Check Wazuh reachable
    wazuh_ok = False
    try:
        wazuh_url = os.getenv("WAZUH_URL", "https://172.17.0.1:55000")
        r = requests.get(wazuh_url, verify=False, timeout=3)
        wazuh_ok = r.status_code < 500
    except Exception:
        wazuh_ok = False

    # Check Cowrie log exists
    cowrie_log_path = Path(os.getenv("COWRIE_LOG_PATH", "/var/log/cowrie/cowrie.json"))
    cowrie_ok = cowrie_log_path.exists()

    return {
        "status": "ok",
        "vm": "165.232.174.172",
        "services": {
            "groq": bool(os.getenv("GROQ_API_KEY")),
            "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
            "wazuh": wazuh_ok,
            "cowrie": cowrie_ok,
            "pfsense": False,
        },
        "storage": {
            "samples_writable": os.access(
                os.getenv("SAMPLES_PATH", "/tmp/samples"), os.W_OK
            ),
            "reports_writable": os.access(
                os.getenv("REPORTS_OUTPUT_PATH", "/tmp/reports"), os.W_OK
            ),
        }
    }
