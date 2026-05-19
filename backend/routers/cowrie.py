from __future__ import annotations

import os
from fastapi import APIRouter, HTTPException

from services.cowrie_service import list_cowrie_samples, parse_cowrie_logs

router = APIRouter(tags=['cowrie'])

COWRIE_LOG_PATH = os.getenv("COWRIE_LOG_PATH", "/var/log/cowrie/cowrie.json")
COWRIE_DOWNLOADS_PATH = os.getenv("COWRIE_DOWNLOADS_PATH", "/var/log/cowrie/downloads")


@router.get('/cowrie/logs', response_model=list)
def get_cowrie_logs(limit: int = 100):
    try:
        logs = parse_cowrie_logs(log_path=COWRIE_LOG_PATH, limit=limit)
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch Cowrie logs: {str(e)}")


@router.get('/cowrie/samples', response_model=list)
def get_cowrie_samples():
    try:
        samples = list_cowrie_samples(downloads_path=COWRIE_DOWNLOADS_PATH)
        return samples
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch Cowrie samples: {str(e)}")
