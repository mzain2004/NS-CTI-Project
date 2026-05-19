from __future__ import annotations

import os
import time
import aiohttp
import json
from pathlib import Path
from fastapi import HTTPException

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
TMP_PATH = Path("/tmp/samples")

from models.analysis import VirusTotalEngineHit, VirusTotalResult


async def lookup_hash(sha256: str) -> dict:
    """Lookup a file hash in VirusTotal and return the result."""
    url = f"{VT_BASE_URL}/files/{sha256}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 404:
                    return {"not_found": True, "sha256": sha256}
                elif response.status == 429:
                    time.sleep(60)
                    async with session.get(url, headers=headers) as retry_response:
                        if retry_response.status != 200:
                            raise HTTPException(status_code=retry_response.status, detail="Rate limit exceeded")
                        data = await retry_response.json()
                elif response.status != 200:
                    raise HTTPException(status_code=response.status, detail="Error fetching data from VirusTotal")
                else:
                    data = await response.json()

            attributes = data.get("data", {}).get("attributes", {})
            result = {
                "last_analysis_stats": attributes.get("last_analysis_stats"),
                "detection_ratio": f"{attributes.get('last_analysis_stats', {}).get('malicious', 0)}/"
                                   f"{sum(attributes.get('last_analysis_stats', {}).values())}",
                "last_analysis_results": [
                    {"engine_name": engine, "result": details.get("category")}
                    for engine, details in attributes.get("last_analysis_results", {}).items()
                    if details.get("category") in ["malicious", "suspicious"]
                ][:15],
                "first_submission_date": attributes.get("first_submission_date"),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "popular_threat_classification": attributes.get("popular_threat_classification", {}).get("suggested_threat_label"),
                "names": attributes.get("names"),
                "community_score": attributes.get("reputation"),
                "vt_link": f"https://www.virustotal.com/gui/file/{sha256}"
            }

            result_path = TMP_PATH / sha256 / "virustotal.json"
            result_path.parent.mkdir(parents=True, exist_ok=True)
            with result_path.open("w") as f:
                json.dump(result, f, indent=4)

            return result

        except Exception as e:
            return {"error": str(e), "sha256": sha256}


def get_virustotal_result(file_hash: str) -> VirusTotalResult:
    """TODO: Integrate VirusTotal API v3."""
    return VirusTotalResult(
        detection_ratio='0/72',
        detections=0,
        total_engines=72,
        malicious=0,
        suspicious=0,
        undetected=72,
        engine_hits=[VirusTotalEngineHit(engine='SampleEngine', result='undetected')],
        first_seen=None,
        last_seen=None,
        community_score=0,
        vt_link=f'https://www.virustotal.com/gui/file/{file_hash}',
        family_names=[],
    )
