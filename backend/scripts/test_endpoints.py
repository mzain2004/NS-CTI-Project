import os
import sys
from pathlib import Path

# Add backend directory to path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_endpoints():
    print("Testing /api/demo/seed...")
    response = client.get("/api/demo/seed")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    print("Seed response:", data)
    assert data["seeded"] is True
    assert data["counts"]["sessions"] == 5
    assert data["counts"]["analyses"] == 3
    assert data["counts"]["alerts"] == 10

    print("\nTesting /api/cowrie/sessions...")
    response = client.get("/api/cowrie/sessions")
    assert response.status_code == 200
    sessions = response.json()
    print(f"Sessions: {len(sessions)} returned")
    assert len(sessions) == 5
    assert sessions[0]["src_ip"] == "185.220.101.45"

    print("\nTesting /api/cowrie/logs (logs endpoint)...")
    response = client.get("/api/cowrie/logs")
    assert response.status_code == 200
    logs = response.json()
    print(f"Logs: {len(logs)} returned")
    assert len(logs) == 5

    print("\nTesting /api/analyze/list...")
    response = client.get("/api/analyze/list")
    assert response.status_code == 200
    analyses = response.json()
    print(f"Analyses: {len(analyses)} returned")
    assert len(analyses) == 3
    # Check that threat count calculation will yield exactly 2
    threats = [a for a in analyses if (a.get("groq_analysis", {}).get("risk_level") or a.get("risk_level", "LOW")).upper() != "LOW"]
    print(f"Threats count (non-LOW): {len(threats)}")
    assert len(threats) == 2, f"Expected 2 threats, got {len(threats)}"
    # Check IoCs count
    iocs_total = 0
    for a in analyses:
        iocs = a.get("groq_analysis", {}).get("iocs", {})
        iocs_total += sum(len(iocs.get(k, [])) for k in ["ips", "domains", "urls", "hashes", "registry_keys", "file_paths", "mutexes"])
    print(f"Total IoCs: {iocs_total}")
    assert iocs_total == 8, f"Expected 8 IoCs, got {iocs_total}"

    print("\nTesting /api/wazuh/alerts...")
    response = client.get("/api/wazuh/alerts")
    assert response.status_code == 200
    alerts = response.json()
    print(f"Alerts: {len(alerts)} returned")
    assert len(alerts) == 10

    print("\nTesting /api/wazuh/stats...")
    response = client.get("/api/wazuh/stats")
    assert response.status_code == 200
    stats = response.json()
    print("Wazuh stats response:", stats)
    assert stats["total_alerts"] == 10

    print("\nAll endpoint tests passed successfully!")

if __name__ == "__main__":
    test_endpoints()
