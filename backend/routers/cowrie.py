from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from services.cowrie_service import get_cowrie_logs, list_cowrie_samples, parse_cowrie_logs

router = APIRouter(tags=['cowrie'])


@router.get('/cowrie/logs')
async def cowrie_logs(limit: int = 20):
    return JSONResponse(status_code=503, content={"status": "not_configured", "message": "Cowrie honeypot not yet deployed. See /docs for setup."})


@router.get('/cowrie/samples')
async def cowrie_samples():
    return JSONResponse(status_code=503, content={"status": "not_configured", "message": "Cowrie honeypot not yet deployed. See /docs for setup."})


@router.get("/api/cowrie/logs", response_model=list)
def get_cowrie_logs(limit: int = 100):
    try:
        logs = parse_cowrie_logs(limit=limit)
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch Cowrie logs: {str(e)}")


@router.get("/api/cowrie/samples", response_model=list)
def get_cowrie_samples():
    try:
        samples = list_cowrie_samples()
        return samples
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch Cowrie samples: {str(e)}")
