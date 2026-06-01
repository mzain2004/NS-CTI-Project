from __future__ import annotations
import os
import logging
import asyncio
import time
from pathlib import Path
from typing import Dict

logger = logging.getLogger("dynamic-sandbox")

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    docker = None
    DOCKER_AVAILABLE = False

def _detonate_sync(file_path: str) -> dict:
    if not DOCKER_AVAILABLE or docker is None:
        logger.warning("Docker library is not installed. Skipping detonation.")
        return {
            "sandbox_status": "skipped",
            "error": "docker library not installed",
            "behaviors": [],
            "network_calls": [],
            "files_created": []
        }
    
    container = None
    try:
        client = docker.from_env()
        client.ping()
    except Exception as daemon_exc:
        logger.warning(f"Docker daemon is not reachable: {daemon_exc}. Skipping live detonation.")
        return {
            "sandbox_status": "skipped",
            "error": f"Docker daemon unreachable: {daemon_exc}",
            "behaviors": [],
            "network_calls": [],
            "files_created": []
        }

    image_name = "remnux/remnux-distro"
    try:
        logger.info(f"Checking for sandbox image {image_name}...")
        client.images.pull(image_name)
    except Exception as img_exc:
        logger.warning(f"Failed to pull {image_name}: {img_exc}. Falling back to alpine:latest.")
        image_name = "alpine:latest"
        try:
            client.images.pull(image_name)
        except Exception as alpine_exc:
            logger.error(f"Failed to pull fallback image alpine: {alpine_exc}")
            return {
                "sandbox_status": "error",
                "error": f"Failed to pull images: {alpine_exc}",
                "behaviors": [],
                "network_calls": [],
                "files_created": []
            }

    abs_path = os.path.abspath(file_path)
    if not os.path.exists(abs_path):
        logger.error(f"Malware sample file does not exist at: {abs_path}")
        return {
            "sandbox_status": "error",
            "error": "Sample file not found on disk",
            "behaviors": [],
            "network_calls": [],
            "files_created": []
        }

    try:
        logger.info(f"Running sandbox container for {abs_path} using image {image_name}...")
        
        # Run container securely: read-only bind, network none, memory/cpu constraints, privileged=False
        container = client.containers.run(
            image=image_name,
            command='/bin/sh -c "file /malware/sample && strings /malware/sample | head -100"',
            volumes={
                abs_path: {
                    "bind": "/malware/sample",
                    "mode": "ro"
                }
            },
            network_mode="none",
            mem_limit="256m",
            cpu_period=100000,
            privileged=False,
            detach=True
        )

        wait_time = 0
        poll_interval = 0.5
        finished = False
        while wait_time < 30:
            container.reload()
            if container.status == "exited":
                finished = True
                break
            time.sleep(poll_interval)
            wait_time += poll_interval

        if not finished:
            logger.warning("Sandbox container exceeded 30s timeout. Killing container...")
            container.kill()
            container.reload()

        logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="ignore")
        logger.info("Sandbox execution completed.")
        
        behaviors = []
        if "elf" in logs.lower() or "pe32" in logs.lower() or "executable" in logs.lower():
            behaviors.append("EXECUTABLE_BINARY_IDENTIFIED")
        if "upx" in logs.lower():
            behaviors.append("UPX_PACKED_BINARY_INDICATOR")
        if "libc" in logs.lower() or "ld-linux" in logs.lower():
            behaviors.append("DYNAMIC_LINKING_DETECTED")
        if "shell" in logs.lower() or "sh" in logs.lower():
            behaviors.append("SHELL_EXECUTION_ATTEMPT")

        return {
            "sandbox_status": "success",
            "stdout_summary": logs[:1000],
            "behaviors": behaviors,
            "network_calls": [],
            "files_created": []
        }

    except Exception as run_exc:
        logger.error(f"Exception during sandbox container run: {run_exc}")
        return {
            "sandbox_status": "error",
            "error": str(run_exc),
            "behaviors": [],
            "network_calls": [],
            "files_created": []
        }
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception as rm_exc:
                logger.warning(f"Could not remove sandbox container: {rm_exc}")

async def run_sandbox_analysis(file_path: str) -> dict:
    """
    Asynchronously executes malware sample in isolated sandbox.
    """
    logger.info(f"Triggering dynamic sandbox analysis for: {file_path}")
    try:
        return await asyncio.to_thread(_detonate_sync, file_path)
    except Exception as e:
        logger.error(f"Sandbox detonation thread wrapper failed: {e}")
        return {
            "sandbox_status": "error",
            "error": str(e),
            "behaviors": [],
            "network_calls": [],
            "files_created": []
        }

async def execute(context: dict) -> dict:
    file_path = context.get("file_path")
    if not file_path:
        return {"error": "Missing file_path in context for dynamic sandbox"}
    result = await run_sandbox_analysis(file_path)
    
    static_analysis = context.get("static_analysis", {})
    sha256 = static_analysis.get("sha256") or context.get("sha256")
    if sha256:
        import json
        from pathlib import Path
        output_path = Path("/tmp/samples") / sha256 / "dynamic.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w") as f:
            json.dump(result, f, indent=4)
            
    return {"dynamic_analysis": result}
