from fastapi import FastAPI, Request
import asyncio
import httpx
import logging
import os

# Configuration
VT_API_KEY = os.getenv("VT_API_KEY", "YOUR_VT_API_KEY")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "YOUR_DISCORD_WEBHOOK_URL")
VT_RATE_LIMIT_DELAY = 15  # 60s / 4 = 15s delay

app = FastAPI(title="AutoShield Middleware")
vt_queue = asyncio.Queue()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("autoshield")

async def get_vt_score(client, resource, is_file=True):
    type_path = "files" if is_file else "ip_addresses"
    url = f"https://www.virustotal.com/api/v3/{type_path}/{resource}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = await client.get(url, headers=headers)
        if response.status_code == 200:
            attributes = response.json().get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            return stats.get("malicious", 0)
    except Exception as e:
        logger.error(f"VT API Error: {e}")
    return 0

async def discord_alert(client, ip, score, sha256=None):
    payload = {
        "embeds": [{
            "title": "🛡️ AutoShield: Threat Detected",
            "color": 15158332, # Red
            "fields": [
                {"name": "Attacker IP", "value": f"`{ip}`", "inline": True},
                {"name": "VT Malicious Score", "value": f"`{score}`", "inline": True},
                {"name": "File Hash (SHA256)", "value": f"`{sha256 or 'N/A'}`", "inline": False}
            ],
            "footer": {"text": "Autonomous Defense System"}
        }]
    }
    await client.post(DISCORD_WEBHOOK_URL, json=payload)

async def worker():
    logger.info("VirusTotal Worker started.")
    async with httpx.AsyncClient() as client:
        while True:
            item = await vt_queue.get()
            ip = item.get("ip")
            sha256 = item.get("sha256")
            
            logger.info(f"Processing threat info for IP: {ip}")
            
            score = 0
            if sha256:
                score = await get_vt_score(client, sha256, is_file=True)
            elif ip:
                score = await get_vt_score(client, ip, is_file=False)
            
            if score >= 3: # Threshold for high threat
                logger.info(f"High threat detected! Score: {score}. Sending alert.")
                await discord_alert(client, ip, score, sha256)
            
            await asyncio.sleep(VT_RATE_LIMIT_DELAY)
            vt_queue.task_done()

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(worker())

@app.post("/webhook")
async def handle_wazuh_webhook(request: Request):
    alert = await request.json()
    
    # Extract data from Wazuh JSON format
    # Cowrie events in Wazuh often appear in 'data' field
    data = alert.get("data", {})
    ip = data.get("srcip") or data.get("src_ip")
    sha256 = data.get("sha256")
    
    if ip:
        await vt_queue.put({"ip": ip, "sha256": sha256})
        return {"message": "Alert queued for VT analysis"}
    
    return {"message": "No actionable data found in alert"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
