from __future__ import annotations

from fastapi import APIRouter, HTTPException, Body
from fastapi.responses import JSONResponse

from models.pfsense import BlockRequest
from services.pfsense_service import block_ip

router = APIRouter(tags=['pfsense'])


@router.post('/pfsense/block')
async def block(request: BlockRequest):
    try:
        return block_ip(request)
    except Exception as exc:
        return JSONResponse(status_code=500, content={'error': f'pfsense_block_failed: {exc}'})
@router.get("/api/pfsense/rules", response_model=dict)
async def get_rules():
    raise HTTPException(status_code=503, detail={"status": "not_configured", "message": "pfSense API credentials required"})

@router.get("/api/pfsense/blocked", response_model=dict)
async def get_blocked_ips():
    raise HTTPException(status_code=503, detail={"status": "not_configured", "message": "pfSense API credentials required"})

@router.post("/api/pfsense/block", response_model=dict)
async def block_ips(ips: list[str] = Body(...), analysis_id: str = Body(...), reason: str = Body(...)):
    raise HTTPException(status_code=503, detail={"status": "not_configured", "message": "pfSense API credentials required"})

@router.delete("/api/pfsense/block/{ip}", response_model=dict)
async def unblock_ip(ip: str):
    raise HTTPException(status_code=503, detail={"status": "not_configured", "message": "pfSense API credentials required"})
