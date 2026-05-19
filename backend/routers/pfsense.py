from __future__ import annotations

from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel
from services.pfsense_service import block_ip

router = APIRouter(tags=['pfsense'])


class BlockRequest(BaseModel):
    ip: str
    reason: str
    analysis_id: str | None = None


@router.post('/pfsense/block')
async def block(request: BlockRequest):
    try:
        return await block_ip(
            ip=request.ip,
            reason=request.reason,
            analysis_id=request.analysis_id
        )
    except NotImplementedError as e:
        raise HTTPException(status_code=503, detail={"status": "not_configured", "message": str(e)})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to block IP: {str(e)}")


@router.get('/pfsense/rules', response_model=dict)
async def get_rules():
    raise HTTPException(status_code=503, detail={"status": "not_configured", "message": "pfSense API credentials required"})


@router.get('/pfsense/blocked', response_model=dict)
async def get_blocked_ips():
    raise HTTPException(status_code=503, detail={"status": "not_configured", "message": "pfSense API credentials required"})


@router.delete('/pfsense/block/{ip}', response_model=dict)
async def unblock_ip(ip: str):
    raise HTTPException(status_code=503, detail={"status": "not_configured", "message": "pfSense API credentials required"})
