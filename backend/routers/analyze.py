from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

from fastapi import APIRouter, File, UploadFile, HTTPException

from models.analysis import AnalysisResult, StaticAnalysis, GroqAnalysis, VirusTotalResult, VirusTotalEngineHit
from services.groq_service import analyze_with_groq
from services.static_analysis import run_full_analysis
from services.virustotal_service import lookup_hash

router = APIRouter(tags=['analyze'])

SAMPLES_PATH = Path('/tmp/samples')


@router.post('/analyze', response_model=AnalysisResult)
async def analyze_file(
    file: UploadFile = File(None),
    file_path: str = None,
    cowrie_sample: str = None
) -> AnalysisResult:
    try:
        if file:
            content = await file.read()
            sha256 = hashlib.sha256(content).hexdigest()
            sample_dir = SAMPLES_PATH / sha256 / 'original'
            sample_dir.parent.mkdir(parents=True, exist_ok=True)
            with sample_dir.open('wb') as f:
                f.write(content)
            file_path = str(sample_dir)
            filename = file.filename
        elif file_path:
            file_path = Path(file_path)
            sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
            filename = file_path.name
        elif cowrie_sample:
            file_path = Path(cowrie_sample)
            sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
            filename = file_path.name
        else:
            raise HTTPException(status_code=400, detail="No valid input provided")

        # Run the Agentic Orchestrator
        import uuid
        from models.state import AgentState
        from services.orchestrator import Orchestrator

        initial_state = AgentState(
            task_id=uuid.uuid4(),
            context={
                "file_path": str(file_path),
                "filename": filename,
                "sha256": sha256
            }
        )

        final_state = await Orchestrator.run(task="analyze", state=initial_state)

        # Extract results from orchestrator context
        static_result = final_state.context.get("static_analysis")
        groq_result = final_state.context.get("groq_analysis")
        vt_result = final_state.context.get("virustotal")

        # Build structures matching Pydantic validation schemas
        static_model = None
        if static_result:
            static_model = StaticAnalysis.model_validate(static_result)
        
        groq_model = None
        if groq_result and "error" not in groq_result:
            try:
                if isinstance(groq_result, dict) and "raw_response" not in groq_result:
                    groq_result["raw_response"] = ""
                groq_model = GroqAnalysis.model_validate(groq_result)
            except Exception:
                pass

        vt_model = None
        if vt_result and "error" not in vt_result:
            try:
                stats = vt_result.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                total_engines = sum(stats.values()) if stats else 0
                detections = malicious + suspicious
                
                engine_hits = []
                for item in vt_result.get("last_analysis_results", []):
                    engine_hits.append(VirusTotalEngineHit(
                        engine=item.get("engine_name", "Unknown"),
                        result=item.get("result", "undetected")
                    ))

                vt_model = VirusTotalResult(
                    detection_ratio=vt_result.get("detection_ratio", "0/0"),
                    detections=detections,
                    total_engines=total_engines,
                    malicious=malicious,
                    suspicious=suspicious,
                    undetected=undetected,
                    engine_hits=engine_hits,
                    first_seen=str(vt_result.get("first_submission_date")) if vt_result.get("first_submission_date") else None,
                    last_seen=str(vt_result.get("last_analysis_date")) if vt_result.get("last_analysis_date") else None,
                    community_score=vt_result.get("community_score", 0),
                    vt_link=vt_result.get("vt_link", f"https://www.virustotal.com/gui/file/{sha256}"),
                    family_names=vt_result.get("names", []) if isinstance(vt_result.get("names"), list) else [],
                )
            except Exception:
                pass

        analysis_res = AnalysisResult(
            analysis_id=sha256,
            status='complete',
            created_at=datetime.now(tz=timezone.utc).isoformat(),
            file_name=filename,
            static_analysis=static_model,
            groq_analysis=groq_model,
            virustotal=vt_model,
            error=None,
        )

        result_path = SAMPLES_PATH / sha256 / 'result.json'
        with result_path.open('w') as f:
            json.dump(analysis_res.model_dump(), f, indent=4)

        return analysis_res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


SEEDED_SHA256S = {
    "a3f1e2d4b5c6789012345678901234567890abcdef1234567890abcdef123456",
    "b4c2f3e5a6d7890123456789012345678901bcdef2345678901bcdef234567",
    "c5d3g4f6b7e8901234567890123456789012cdef3456789012cdef3456789"
}

def get_seeded_analyses():
    # Attempt to load from disk first (written by the seed script)
    seeded_list = []
    for sha in SEEDED_SHA256S:
        p = SAMPLES_PATH / sha / 'result.json'
        if p.exists():
            try:
                with p.open('r') as f:
                    seeded_list.append(AnalysisResult.model_validate(json.load(f)))
            except Exception:
                pass
    if len(seeded_list) == 3:
        return seeded_list

    # Fallback to hardcoded ones if not seeded on disk yet
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    
    return [
        AnalysisResult(
            analysis_id="a3f1e2d4b5c6789012345678901234567890abcdef1234567890abcdef123456",
            status="complete",
            created_at=(now - timedelta(hours=2)).isoformat(),
            file_name="mirai_sample.elf",
            static_analysis={
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
            groq_analysis={
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
            virustotal={
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
            error=None
        ),
        AnalysisResult(
            analysis_id="b4c2f3e5a6d7890123456789012345678901bcdef2345678901bcdef234567",
            status="complete",
            created_at=(now - timedelta(hours=6)).isoformat(),
            file_name="reverse_shell.sh",
            static_analysis={
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
            groq_analysis={
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
            virustotal={
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
            error=None
        ),
        AnalysisResult(
            analysis_id="c5d3g4f6b7e8901234567890123456789012cdef3456789012cdef3456789",
            status="complete",
            created_at=(now - timedelta(hours=12)).isoformat(),
            file_name="cryptominer.elf",
            static_analysis={
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
            groq_analysis={
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
                "risk_level": "LOW",
                "recommended_actions": ["Kill xmrig processes", "Remove binary from /tmp/xmrig"],
                "analyst_notes": "XMRig Miner",
                "raw_response": ""
            },
            virustotal={
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
            error=None
        )
    ]


@router.get('/analyze/list', response_model=list[AnalysisResult])
async def list_analyses() -> list[AnalysisResult]:
    try:
        analyses = []
        if SAMPLES_PATH.exists():
            for sample_dir in SAMPLES_PATH.iterdir():
                if sample_dir.is_dir():
                    result_path = sample_dir / 'result.json'
                    if result_path.exists():
                        with result_path.open('r') as f:
                            data = json.load(f)
                            analyses.append(AnalysisResult.model_validate(data))
        
        # Determine real analyses (not in seeded set)
        real_analyses = [a for a in analyses if a.analysis_id not in SEEDED_SHA256S]
        if real_analyses:
            return sorted(real_analyses, key=lambda x: x.created_at, reverse=True)
        else:
            return sorted(get_seeded_analyses(), key=lambda x: x.created_at, reverse=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list analyses: {str(e)}")


@router.get('/analyze/{analysis_id}', response_model=AnalysisResult)
async def get_analysis(analysis_id: str) -> AnalysisResult:
    try:
        # Search by exact SHA256 directory name
        result_path = SAMPLES_PATH / analysis_id / 'result.json'
        if result_path.exists():
            with result_path.open('r') as f:
                data = json.load(f)
                return AnalysisResult.model_validate(data)
        
        # Fallback to search directories starting with analysis_id
        if SAMPLES_PATH.exists():
            for sample_dir in SAMPLES_PATH.iterdir():
                if sample_dir.is_dir() and sample_dir.name.startswith(analysis_id):
                    result_path = sample_dir / 'result.json'
                    if result_path.exists():
                        with result_path.open('r') as f:
                            data = json.load(f)
                            return AnalysisResult.model_validate(data)

        # Fallback for seeded analyses if not on disk yet
        for seeded in get_seeded_analyses():
            if seeded.analysis_id.startswith(analysis_id):
                return seeded

        raise HTTPException(status_code=404, detail="Analysis not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch analysis: {str(e)}")
