from __future__ import annotations

import os
import time
import aiohttp
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict
from urllib3.exceptions import InsecureRequestWarning
import warnings

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Wazuh runs on host (not in Docker). From container, reach it via:
# - 172.17.0.1 = Docker bridge gateway on Linux
# - Fallback to env var for custom Wazuh URL
WAZUH_URL = os.getenv("WAZUH_URL", "https://172.17.0.1:55000")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD") or os.getenv("WAZUH_PASS")

_token_cache = {"token": None, "expiry": None}

async def get_wazuh_token() -> str:
    if _token_cache["token"] and _token_cache["expiry"] > datetime.utcnow():
        return _token_cache["token"]

    url = f"{WAZUH_URL}/security/user/authenticate"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, auth=aiohttp.BasicAuth(WAZUH_USER, WAZUH_PASSWORD), ssl=False) as response:
            if response.status != 200:
                raise Exception("Failed to authenticate with Wazuh API")
            data = await response.json()
            _token_cache["token"] = data["data"]["token"]
            _token_cache["expiry"] = datetime.utcnow() + timedelta(minutes=15)
            return _token_cache["token"]

async def get_alerts(limit: int = 100, offset: int = 0) -> List[Dict]:
    url = f"{WAZUH_URL}/alerts?limit={limit}&offset={offset}&sort=-timestamp"
    token = await get_wazuh_token()
    headers = {"Authorization": f"Bearer {token}"}

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, ssl=False) as response:
            if response.status != 200:
                raise Exception("Failed to fetch alerts from Wazuh API")
            data = await response.json()
            alerts = []
            for alert in data.get("data", {}).get("alerts", []):
                alerts.append({
                    "alert_id": alert.get("id"),
                    "timestamp": alert.get("timestamp"),
                    "rule_id": alert.get("rule", {}).get("id"),
                    "rule_level": alert.get("rule", {}).get("level"),
                    "rule_description": alert.get("rule", {}).get("description"),
                    "agent_id": alert.get("agent", {}).get("id"),
                    "agent_name": alert.get("agent", {}).get("name"),
                    "agent_ip": alert.get("agent", {}).get("ip"),
                    "full_log": alert.get("full_log"),
                    "mitre_id": alert.get("rule", {}).get("mitre", {}).get("id", [None])[0],
                    "mitre_technique": alert.get("rule", {}).get("mitre", {}).get("technique", [None])[0],
                    "location": alert.get("location"),
                })
            return alerts

async def correlate_iocs(iocs: Dict) -> List[Dict]:
    token = await get_wazuh_token()
    headers = {"Authorization": f"Bearer {token}"}
    alerts = []

    async with aiohttp.ClientSession() as session:
        for ip in iocs.get("ips", []):
            url = f"{WAZUH_URL}/alerts?q=data.srcip:{ip}"
            async with session.get(url, headers=headers, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    alerts.extend(data.get("data", {}).get("alerts", []))

        for domain in iocs.get("domains", []):
            url = f"{WAZUH_URL}/alerts?q=data.srcip:{domain}"
            async with session.get(url, headers=headers, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    alerts.extend(data.get("data", {}).get("alerts", []))

    return alerts

async def get_stats() -> Dict:
    token = await get_wazuh_token()
    headers = {"Authorization": f"Bearer {token}"}

    async with aiohttp.ClientSession() as session:
        async with session.get(f"{WAZUH_URL}/overview/agents", headers=headers, ssl=False) as agents_response:
            if agents_response.status != 200:
                raise Exception("Failed to fetch agent overview from Wazuh API")
            agents_data = await agents_response.json()
            agents_active = agents_data.get("data", {}).get("totalActive", 0)

        async with session.get(f"{WAZUH_URL}/alerts?limit=1", headers=headers, ssl=False) as alerts_response:
            if alerts_response.status != 200:
                raise Exception("Failed to fetch alerts overview from Wazuh API")
            alerts_data = await alerts_response.json()
            total_alerts = alerts_data.get("total", 0)

        return {
            "total_alerts": total_alerts,
            "critical_alerts": 0,  # Placeholder for critical alert count
            "high_alerts": 0,      # Placeholder for high alert count
            "agents_active": agents_active,
        }

# WAZUH INTEGRATION READY — deploy Wazuh then set WAZUH_URL/USER/PASS in .env

def get_wazuh_alerts(limit: int = 20):
    return {"status": "not_configured", "message": "Wazuh not yet deployed"}


async def execute(context: dict) -> dict:
    limit = context.get("limit", 10)
    try:
        alerts = await get_alerts(limit=limit)
        return {"wazuh_alerts": alerts}
    except Exception as e:
        return {"wazuh_alerts": [], "wazuh_error": str(e)}
