from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

from fastapi import APIRouter, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse

from models.analysis import AnalysisResult
from services.groq_service import analyze_with_groq
from services.static_analysis import run_full_analysis
from services.virustotal_service import get_virustotal_result, lookup_hash

router = APIRouter(tags=['analyze'])

SAMPLES_PATH = Path('/tmp/samples')


@router.post('/analyze', response_model=AnalysisResult)
async def analyze_file(file: UploadFile = File(...)) -> AnalysisResult | JSONResponse:
    try:
        content = await file.read()
        static_result = run_full_analysis(content, file.filename)
        groq_result = analyze_with_groq(static_result)
        vt_result = get_virustotal_result(static_result.sha256)

        return AnalysisResult(
            analysis_id=f'anl_{static_result.sha256[:12]}',
            status='complete',
            created_at=datetime.now(tz=timezone.utc).isoformat(),
            file_name=file.filename,
            static_analysis=static_result,
            groq_analysis=groq_result,
            virustotal=vt_result,
            error=None,
        )
    except Exception as exc:
        return JSONResponse(status_code=500, content={'error': f'analysis_failed: {exc}'})


@router.get('/analyze/{analysis_id}', response_model=AnalysisResult)
async def get_analysis(analysis_id: str) -> AnalysisResult | JSONResponse:
    try:
        return AnalysisResult(
            analysis_id=analysis_id,
            status='complete',
            created_at=datetime.now(tz=timezone.utc).isoformat(),
            file_name='placeholder.bin',
            static_analysis=None,
            groq_analysis=None,
            virustotal=None,
            error=None,
        )
    except Exception as exc:
        return JSONResponse(status_code=500, content={'error': f'analysis_fetch_failed: {exc}'})


@router.post('/api/analyze', response_model=dict)
async def analyze_file(
    file: UploadFile = File(None),
    file_path: str = None,
    cowrie_sample: str = None
):
    try:
        if file:
            content = await file.read()
            sha256 = hashlib.sha256(content).hexdigest()
            sample_dir = SAMPLES_PATH / sha256 / 'original'
            sample_dir.parent.mkdir(parents=True, exist_ok=True)
            with (sample_dir).open('wb') as f:
                f.write(content)
            file_path = str(sample_dir)
        elif file_path:
            file_path = Path(file_path)
        elif cowrie_sample:
            file_path = Path(cowrie_sample)
        else:
            raise HTTPException(status_code=400, detail="No valid input provided")

        # Run static analysis
        static_result = await run_full_analysis(Path(file_path), file.filename if file else Path(file_path).name)
        analysis_id = static_result['hashes']['sha256'][:16] + datetime.now().strftime('%Y%m%d%H%M%S')
        result_path = SAMPLES_PATH / static_result['hashes']['sha256'] / 'result.json'

        # Run Groq analysis
        groq_result = await analyze_with_groq(static_result)
        static_result['groq_analysis'] = groq_result

        # Run VirusTotal lookup
        vt_result = await lookup_hash(static_result['hashes']['sha256'])
        static_result['virustotal'] = vt_result

        # Save combined result
        with result_path.open('w') as f:
            json.dump(static_result, f, indent=4)

        return {"analysis_id": analysis_id, "result": static_result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get('/api/analyze/{analysis_id}', response_model=dict)
def get_analysis(analysis_id: str):
    try:
        for sample_dir in SAMPLES_PATH.iterdir():
            if sample_dir.name.startswith(analysis_id):
                result_path = sample_dir / 'result.json'
                if result_path.exists():
                    with result_path.open('r') as f:
                        return json.load(f)
        raise HTTPException(status_code=404, detail="Analysis not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch analysis: {str(e)}")


@router.get('/api/analyze/list', response_model=list)
def list_analyses():
    try:
        analyses = []
        for sample_dir in SAMPLES_PATH.iterdir():
            result_path = sample_dir / 'result.json'
            if result_path.exists():
                with result_path.open('r') as f:
                    analyses.append(json.load(f))
        return sorted(analyses, key=lambda x: x['created_at'], reverse=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list analyses: {str(e)}")
