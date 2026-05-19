# NS-CTI Project

Monorepo for the Malware Analysis & Threat Intelligence Platform.
**Single-VM Deployment:** 165.232.174.172

## Structure

- frontend: Next.js 15 App Router UI
- backend: FastAPI API and service orchestration
- packages/shared: Shared TypeScript models and constants
- cowrie: Honeypot configuration (docker-compose)
- wazuh-config: Wazuh helper assets (separate deployment)

## Single-VM Deployment (165.232.174.172)

### Prerequisites
- Docker & Docker Compose installed
- GROQ API key
- VirusTotal API key

### Quick Start

1. **Clone or pull the repo:**
```bash
cd /path/to/NS-CTI\ Project
```

2. **Set up backend environment:**
```bash
cp backend/.env.example backend/.env
# Edit backend/.env with your GROQ & VirusTotal keys
```

3. **Build and start entire stack:**
```bash
docker-compose up --build
```

4. **Access the platform:**
   - **Frontend:** http://165.232.174.172 (proxied via nginx)
   - **Backend API:** http://165.232.174.172:8000/docs
   - **Health Check:** http://165.232.174.172:8000/api/health

### Services in Docker Compose

| Service  | Container Port | Host Port | Notes |
|----------|---|---|---|
| nginx    | 80 | 80 | Reverse proxy to frontend & backend |
| frontend | 3000 | (internal) | Next.js app, proxied by nginx |
| backend  | 8000 | 8000 | FastAPI, also exposed directly |
| cowrie   | 2222, 2223 | 2222, 2223 | Honeypot SSH/Telnet |

### Wazuh Deployment (Separate)

Wazuh **does NOT run in docker-compose**. It runs separately via its official stack in `/opt/wazuh-docker`.

**Once Wazuh is deployed on the same VM:**
1. Update `backend/.env`:
   - `WAZUH_URL=https://165.232.174.172:55000`
   - `WAZUH_USER=admin`
   - `WAZUH_PASS=<wazuh_password>`

2. Verify connectivity:
   ```bash
   curl -k https://165.232.174.172:55000/
   ```

3. The backend container reaches Wazuh via `172.17.0.1:55000` (Docker bridge gateway).

## Environment Variables

See `backend/.env.example` for a complete template.

### Required
- `GROQ_API_KEY`: GROQ API key for malware analysis
- `VIRUSTOTAL_API_KEY`: VirusTotal API key for hash lookups

### Optional (Wazuh)
- `WAZUH_URL`: Wazuh manager URL (default: `https://172.17.0.1:55000`)
- `WAZUH_USER`: Wazuh admin username
- `WAZUH_PASS`: Wazuh admin password

### Optional (pfSense)
- `PFSENSE_URL`: pfSense API URL
- `PFSENSE_API_KEY`: pfSense API key

### Storage
- `REPORTS_OUTPUT_PATH`: `/tmp/reports` (inside container, persisted volume)
- `SAMPLES_PATH`: `/tmp/samples` (inside container, persisted volume)
- `COWRIE_LOG_PATH`: `/var/log/cowrie/cowrie.json` (auto-mounted from Cowrie container)

## Docker Compose Volumes

```yaml
samples_data:      # Uploaded malware samples
reports_data:      # Generated PDF reports
cowrie_logs:       # Cowrie honeypot logs
cowrie_downloads:  # Cowrie downloaded files
```
