from __future__ import annotations

import os
import logging
import asyncssh
from typing import List, Dict

logger = logging.getLogger("pfsense-service")

async def block_ip_on_firewall(target_ip: str) -> dict:
    """
    Establish SSH connection to the pfSense firewall and execute:
    easyrule block wan <target_ip>
    """
    host = os.getenv("PFSENSE_HOST")
    user = os.getenv("PFSENSE_USER")
    password = os.getenv("PFSENSE_PASS")

    if not host or not user or not password:
        logger.error("pfSense credentials (PFSENSE_HOST, PFSENSE_USER, PFSENSE_PASS) are missing from environment.")
        return {"status": "error", "message": "pfSense firewall credentials not configured"}

    logger.info(f"Initiating active defense: attempting to block IP {target_ip} on firewall {host} via SSH...")

    try:
        # TODO: Replace StrictHostKeyChecking=no (known_hosts=None) with proper host key validation in production
        async with asyncssh.connect(
            host,
            username=user,
            password=password,
            known_hosts=None
        ) as conn:
            command = f"easyrule block wan {target_ip}"
            logger.info(f"Connected to pfSense. Executing: {command}")
            result = await conn.run(command)

            if result.exit_status == 0:
                logger.info(f"Successfully blocked IP {target_ip} on pfSense. Output: {result.stdout.strip()}")
                return {
                    "status": "success",
                    "ip": target_ip,
                    "exit_status": result.exit_status,
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip()
                }
            else:
                logger.error(f"Failed to execute block command on pfSense. Exit status: {result.exit_status}. Stderr: {result.stderr.strip()}")
                return {
                    "status": "error",
                    "message": "Block command failed",
                    "exit_status": result.exit_status,
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip()
                }

    except asyncssh.Error as ssh_err:
        logger.error(f"SSH authentication or connection error targeting pfSense: {ssh_err}")
        return {"status": "error", "message": f"SSH error: {ssh_err}"}
    except Exception as e:
        logger.error(f"Unexpected error executing pfSense active defense command: {e}")
        return {"status": "error", "message": str(e)}

async def block_ip(ip: str, reason: str = "Manual Block", analysis_id: str | None = None) -> Dict:
    """
    Manual route hook to block a specific IP address in the pfSense firewall.
    """
    res = await block_ip_on_firewall(ip)
    if res.get("status") == "success":
        return {
            "status": "blocked",
            "ip": ip,
            "reason": reason,
            "analysis_id": analysis_id,
            "details": res
        }
    else:
        raise Exception(res.get("message", "Unknown firewall SSH error"))

async def get_firewall_rules() -> List[Dict]:
    raise NotImplementedError("pfSense SSH integration does not support listing firewall rules")

async def block_ip_list(ips: List[str], reason: str, analysis_id: str) -> List[Dict]:
    results = []
    for ip in ips:
        try:
            res = await block_ip(ip, reason, analysis_id)
            results.append(res)
        except Exception as e:
            results.append({"status": "error", "ip": ip, "message": str(e)})
    return results

async def unblock_ip(ip: str) -> Dict:
    """
    Optional unblock execution path using easyrule.
    """
    host = os.getenv("PFSENSE_HOST")
    user = os.getenv("PFSENSE_USER")
    password = os.getenv("PFSENSE_PASS")

    if not host or not user or not password:
        raise NotImplementedError("pfSense credentials not configured")

    try:
        # TODO: Replace StrictHostKeyChecking=no (known_hosts=None) with proper host key validation in production
        async with asyncssh.connect(host, username=user, password=password, known_hosts=None) as conn:
            result = await conn.run(f"easyrule unblock wan {ip}")
            if result.exit_status == 0:
                return {"status": "unblocked", "ip": ip, "stdout": result.stdout.strip()}
            else:
                raise Exception(f"Unblock failed: {result.stderr.strip()}")
    except Exception as e:
        logger.error(f"pfSense unblock error: {e}")
        raise Exception(f"Failed to unblock IP: {str(e)}")

async def get_blocked_ips() -> List[Dict]:
    raise NotImplementedError("pfSense SSH integration does not support listing blocked IPs")

async def create_alias(name: str, ips: List[str], description: str) -> Dict:
    raise NotImplementedError("pfSense SSH integration does not support creating aliases")


async def execute(context: dict) -> dict:
    import json
    from pathlib import Path
    attacker_ip = context.get("attacker_ip")
    if not attacker_ip:
        static_analysis = context.get("static_analysis", {})
        sha256 = static_analysis.get("sha256")
        if sha256:
            log_path = os.getenv("COWRIE_LOG_PATH", "/var/log/cowrie/cowrie.json")
            if log_path and Path(log_path).exists():
                try:
                    with open(log_path, "r") as f:
                        for line in f:
                            try:
                                event = json.loads(line)
                                if event.get("eventid") == "cowrie.session.file_download" and event.get("sha256") == sha256:
                                    attacker_ip = event.get("src_ip")
                                    break
                            except Exception:
                                continue
                except Exception:
                    pass

    if not attacker_ip:
        return {"error": "Missing attacker_ip in context for pfSense firewall block"}
    
    result = await block_ip_on_firewall(attacker_ip)
    return {"pfsense_block": result}
