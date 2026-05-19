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
