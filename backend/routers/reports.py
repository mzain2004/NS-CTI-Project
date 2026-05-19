from __future__ import annotations

import os
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, FileResponse

from models.report import ReportGenerateRequest
from services.report_service import generate_report

router = APIRouter(tags=['reports'])

REPORTS_OUTPUT_PATH = Path("/tmp/reports")


@router.post('/report/generate')
async def generate_report_endpoint(request: ReportGenerateRequest):
    try:
        result = await generate_report(request.analysis_id, request.analyst)
        return {
            "report_id": result["report_id"],
            "pdf_url": f"/api/report/{result['report_id']}/pdf",
            "json_url": f"/api/report/{result['report_id']}/json",
            "ioc_url": f"/api/report/{result['report_id']}/iocs",
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(exc)}")


@router.get('/report/{report_id}/pdf')
async def get_report_pdf(report_id: str):
    pdf_path = REPORTS_OUTPUT_PATH / f"{report_id}.pdf"
    if not pdf_path.exists():
        return JSONResponse(status_code=404, content={"error": "PDF not found"})
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"{report_id}.pdf")


@router.get('/report/{report_id}/json')
async def get_report_json(report_id: str):
    json_path = REPORTS_OUTPUT_PATH / f"{report_id}.json"
    if not json_path.exists():
        return JSONResponse(status_code=404, content={"error": "JSON not found"})
    return FileResponse(json_path, media_type="application/json", filename=f"{report_id}.json")


@router.get('/report/{report_id}/iocs')
async def get_report_iocs(report_id: str):
    ioc_path = REPORTS_OUTPUT_PATH / f"{report_id}_iocs.txt"
    if not ioc_path.exists():
        return JSONResponse(status_code=404, content={"error": "IOC file not found"})
    return FileResponse(ioc_path, media_type="text/plain", filename=f"{report_id}_iocs.txt")


@router.get('/report/list')
async def list_reports():
    reports = []
    if REPORTS_OUTPUT_PATH.exists():
        for pdf_file in REPORTS_OUTPUT_PATH.glob("*.pdf"):
            report_id = pdf_file.stem
            reports.append({
                "report_id": report_id,
                "pdf_url": f"/api/report/{report_id}/pdf",
                "json_url": f"/api/report/{report_id}/json",
                "ioc_url": f"/api/report/{report_id}/iocs",
            })
    return reports


@router.delete('/report/{report_id}')
async def delete_report(report_id: str):
    try:
        for ext in [".pdf", ".json", "_iocs.txt"]:
            file_path = REPORTS_OUTPUT_PATH / f"{report_id}{ext}"
            if file_path.exists():
                os.remove(file_path)
        return {"status": "deleted", "report_id": report_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete report: {str(exc)}")
