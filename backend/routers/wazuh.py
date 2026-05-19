from __future__ import annotations

from fastapi import APIRouter, HTTPException, Body
from fastapi.responses import JSONResponse

from services.wazuh_service import get_wazuh_alerts, get_alerts, get_stats, correlate_iocs

router = APIRouter(tags=['wazuh'])


@router.get('/wazuh/alerts')
async def wazuh_alerts(limit: int = 20):
    return JSONResponse(status_code=503, content={"status": "not_configured", "message": "Wazuh not yet deployed. See /docs for setup."})

@router.get("/api/wazuh/alerts", response_model=list)
async def fetch_alerts(limit: int = 100, offset: int = 0):
    try:
        return await get_alerts(limit=limit, offset=offset)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch alerts: {str(e)}")

@router.get("/api/wazuh/stats", response_model=dict)
async def fetch_stats():
    try:
        return await get_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch stats: {str(e)}")

@router.post("/api/wazuh/correlate", response_model=list)
async def correlate_indicators(analysis_id: str = Body(...)):
    try:
        # Load IoCs from result.json (mocked here for simplicity)
        iocs = {"ips": ["192.168.1.1"], "domains": ["example.com"]}  # Replace with actual file loading logic
        return await correlate_iocs(iocs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to correlate IoCs: {str(e)}")
