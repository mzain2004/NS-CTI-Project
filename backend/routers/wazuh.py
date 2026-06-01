from __future__ import annotations

import json
from pathlib import Path
from fastapi import APIRouter, HTTPException, Body

from services.wazuh_service import get_alerts, get_stats, correlate_iocs

router = APIRouter(tags=['wazuh'])

SAMPLES_PATH = Path('/tmp/samples')


@router.get('/wazuh/alerts', response_model=list)
async def fetch_alerts(limit: int = 100, offset: int = 0):
    try:
        return await get_alerts(limit=limit, offset=offset)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch alerts: {str(e)}")


@router.get('/wazuh/stats', response_model=dict)
async def fetch_stats():
    try:
        return await get_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch stats: {str(e)}")


@router.post('/wazuh/correlate', response_model=list)
async def correlate_indicators(analysis_id: str = Body(..., embed=True)):
    try:
        # Load IoCs from result.json
        result_path = SAMPLES_PATH / analysis_id / 'result.json'
        iocs = {"ips": [], "domains": [], "hashes": []}
        if result_path.exists():
            with result_path.open('r') as f:
                data = json.load(f)
                groq_iocs = data.get("groq_analysis", {}).get("iocs", {})
                if groq_iocs:
                    iocs["ips"] = groq_iocs.get("ips", [])
                    iocs["domains"] = groq_iocs.get("domains", [])
                    iocs["hashes"] = groq_iocs.get("hashes", [])
        
        return await correlate_iocs(iocs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to correlate IoCs: {str(e)}")
