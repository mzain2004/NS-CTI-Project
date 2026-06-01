import os
import logging
import httpx
from typing import Dict, Any

logger = logging.getLogger("otx-service")

async def lookup_hash_otx(file_hash: str) -> dict:
    otx_api_key = os.getenv("OTX_API_KEY")
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    
    headers = {}
    if otx_api_key:
        headers["X-OTX-API-KEY"] = otx_api_key

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers)
            
            if response.status_code == 404:
                logger.info(f"Hash {file_hash} not found in AlienVault OTX.")
                return {
                    "pulse_count": 0,
                    "malware_families": [],
                    "threat_score": 0
                }
            elif response.status_code != 200:
                logger.error(f"OTX API returned status {response.status_code} for hash {file_hash}")
                return {
                    "pulse_count": 0,
                    "malware_families": [],
                    "threat_score": 0,
                    "error": f"OTX API error: status {response.status_code}"
                }
            
            data = response.json()
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            pulse_count = len(pulses)
            
            # Extract malware families if available in pulses
            families = set()
            for pulse in pulses:
                for name in pulse.get("malware_families", []):
                    if name:
                        families.add(name)
                for tag in pulse.get("tags", []):
                    if tag.lower() in ["trojan", "ransomware", "adware", "spyware", "worm", "backdoor", "rootkit"]:
                        families.add(tag)
            
            threat_score = min(10, pulse_count)
            
            return {
                "pulse_count": pulse_count,
                "malware_families": list(families),
                "threat_score": threat_score
            }
            
    except Exception as e:
        logger.error(f"Error checking AlienVault OTX for hash {file_hash}: {e}")
        return {
            "pulse_count": 0,
            "malware_families": [],
            "threat_score": 0,
            "error": str(e)
        }

async def execute(context: dict) -> dict:
    sha256 = context.get("sha256")
    if not sha256:
        static_analysis = context.get("static_analysis", {})
        sha256 = static_analysis.get("sha256")
    if not sha256:
        return {"error": "Missing sha256 in context for OTX lookup"}
    
    result = await lookup_hash_otx(sha256)
    return {"otx_enrichment": result}
