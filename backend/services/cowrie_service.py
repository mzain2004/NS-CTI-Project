from __future__ import annotations

from datetime import datetime, timezone

from models.cowrie import CowrieSample, CowrieSession
import os
import json
import hashlib
from pathlib import Path
from geoip import geolite2

COWRIE_DOWNLOADS_PATH = Path("/tmp/cowrie_downloads")


def get_cowrie_logs(limit: int = 20) -> dict:
    """TODO: Parse Cowrie JSON logs from COWRIE_LOG_PATH."""
    return {"status": "not_configured", "message": "Cowrie honeypot not yet deployed"}


def list_cowrie_samples() -> dict:
    """TODO: Enumerate downloaded files from COWRIE_DOWNLOADS_PATH."""
    return {"status": "not_configured", "message": "Cowrie honeypot not yet deployed"}


def parse_cowrie_logs(log_path: str = None, limit: int = 100) -> list[dict]:
    log_path = log_path or "cowrie.json"
    log_file = Path(log_path)
    if not log_file.exists():
        return []

    sessions = {}
    try:
        with log_file.open("r") as f:
            for line in f:
                try:
                    event = json.loads(line)
                    session_id = event.get("session")
                    if not session_id:
                        continue

                    if session_id not in sessions:
                        sessions[session_id] = {
                            "session_id": session_id,
                            "src_ip": event.get("src_ip"),
                            "src_port": event.get("src_port"),
                            "timestamp_start": event.get("timestamp"),
                            "timestamp_end": event.get("timestamp"),
                            "duration_seconds": 0,
                            "protocol": event.get("protocol"),
                            "username_attempts": [],
                            "password_attempts": [],
                            "commands_executed": [],
                            "files_downloaded": [],
                            "login_success": False,
                            "country": None,
                        }

                    session = sessions[session_id]
                    session["timestamp_end"] = event.get("timestamp", session["timestamp_end"])
                    session["duration_seconds"] = (
                        datetime.fromisoformat(session["timestamp_end"]) - datetime.fromisoformat(session["timestamp_start"])
                    ).total_seconds()

                    if event.get("eventid") == "cowrie.command.input":
                        session["commands_executed"].append(event.get("input"))
                    elif event.get("eventid") == "cowrie.session.file_download":
                        session["files_downloaded"].append({
                            "filename": event.get("filename"),
                            "url": event.get("url"),
                            "sha256": event.get("sha256"),
                            "size": event.get("size"),
                        })
                    elif event.get("eventid") == "cowrie.login.success":
                        session["login_success"] = True

                    if not session["country"] and session["src_ip"]:
                        match = geolite2.lookup(session["src_ip"])
                        session["country"] = match.country if match else None

                except json.JSONDecodeError:
                    continue

        return sorted(sessions.values(), key=lambda x: x["timestamp_start"], reverse=True)[:limit]

    except Exception as e:
        return []


def list_cowrie_samples(downloads_path: str = None) -> list[dict]:
    downloads_path = Path(downloads_path or COWRIE_DOWNLOADS_PATH)
    if not downloads_path.exists():
        return []

    samples = []
    for file in downloads_path.iterdir():
        if file.is_file():
            samples.append({
                "filename": file.name,
                "sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
                "size": file.stat().st_size,
                "modified_at": datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
                "full_path": str(file.resolve()),
            })

    return sorted(samples, key=lambda x: x["modified_at"], reverse=True)
