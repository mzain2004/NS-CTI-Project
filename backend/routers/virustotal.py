from __future__ import annotations

from fastapi import APIRouter, HTTPException

from models.analysis import VirusTotalResult, VirusTotalEngineHit
from services.virustotal_service import lookup_hash

router = APIRouter(tags=['virustotal'])


@router.get('/virustotal/{file_hash}', response_model=VirusTotalResult)
async def get_virustotal_analysis(file_hash: str) -> VirusTotalResult:
    try:
        vt_result = await lookup_hash(file_hash)
        if not vt_result or "error" in vt_result:
            raise HTTPException(status_code=404, detail=f"VirusTotal lookup failed: {vt_result.get('error', 'Unknown error')}")
        if vt_result.get("not_found"):
            raise HTTPException(status_code=404, detail="Hash not found in VirusTotal")

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

        return VirusTotalResult(
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
            vt_link=vt_result.get("vt_link", f"https://www.virustotal.com/gui/file/{file_hash}"),
            family_names=vt_result.get("names", []) if isinstance(vt_result.get("names"), list) else [],
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch VirusTotal analysis: {str(e)}")
