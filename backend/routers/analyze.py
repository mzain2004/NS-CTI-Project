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

        raise HTTPException(status_code=404, detail="Analysis not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch analysis: {str(e)}")


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
        return sorted(analyses, key=lambda x: x.created_at, reverse=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list analyses: {str(e)}")
