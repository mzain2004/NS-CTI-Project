from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from services.virustotal_service import get_virustotal_result, lookup_hash

router = APIRouter(tags=['virustotal'])


@router.get('/virustotal/{file_hash}')
async def get_virustotal(file_hash: str):
    try:
        return get_virustotal_result(file_hash)
    except Exception as exc:
        return JSONResponse(status_code=500, content={'error': f'virustotal_failed: {exc}'})


@router.get("/api/virustotal/{hash}", response_model=dict)
async def get_virustotal_analysis(hash: str):
    try:
        result = await lookup_hash(hash)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch VirusTotal analysis: {str(e)}")
