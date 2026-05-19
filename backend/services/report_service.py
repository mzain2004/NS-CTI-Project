from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import uuid
from pathlib import Path
from jinja2 import Template
from weasyprint import HTML

REPORTS_OUTPUT_PATH = Path("/tmp/reports")
REPORTS_OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

from models.analysis import AnalysisResult
from models.report import ReportExport, ReportMetadata


def generate_report_exports(analysis: AnalysisResult, analyst: str, formats: list[str]) -> tuple[ReportMetadata, list[ReportExport]]:
    """TODO: Integrate WeasyPrint PDF + JSON + IOC text output."""
    report_id = f"report_{analysis.analysis_id}"
    metadata = ReportMetadata(
        report_id=report_id,
        analysis_id=analysis.analysis_id,
        file_name=analysis.file_name,
        sha256=analysis.static_analysis.sha256 if analysis.static_analysis else '',
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
        risk_level=analysis.groq_analysis.risk_level if analysis.groq_analysis else 'LOW',
        analyst=analyst,
    )
    exports = [
        ReportExport(
            report_id=report_id,
            format=fmt,
            download_url=f'/api/report/{report_id}?format={fmt}',
        )
        for fmt in formats
    ]
    return metadata, exports


async def generate_report(analysis_id: str, analyst_name: str = "Auto-Generated") -> dict:
    """
    Generate a complete report for the given analysis ID.
    """
    # Load analysis data
    analysis_dir = Path(f"/tmp/samples/{analysis_id}")
    result_path = analysis_dir / "result.json"
    groq_path = analysis_dir / "groq.json"
    vt_path = analysis_dir / "virustotal.json"
    static_path = analysis_dir / "static.json"

    with open(result_path) as f:
        result_data = json.load(f)
    with open(groq_path) as f:
        groq_data = json.load(f)
    with open(vt_path) as f:
        vt_data = json.load(f)
    with open(static_path) as f:
        static_data = json.load(f)

    # Generate report ID
    report_id = str(uuid.uuid4())

    # Prepare IOC data
    iocs = result_data.get("iocs", {})
    ioc_lines = []
    for ip in iocs.get("ips", []):
        ioc_lines.append(f"IP: {ip}")
    for domain in iocs.get("domains", []):
        ioc_lines.append(f"DOMAIN: {domain}")
    for hash in iocs.get("hashes", []):
        ioc_lines.append(f"HASH: {hash}")
    for url in iocs.get("urls", []):
        ioc_lines.append(f"URL: {url}")

    # Save IOC file
    ioc_path = REPORTS_OUTPUT_PATH / f"{report_id}_iocs.txt"
    with open(ioc_path, "w") as f:
        f.write("\n".join(ioc_lines))

    # Generate HTML report
    template = Template("""<!DOCTYPE html>
    <html>
    <head>
        <title>NS-CTI Report</title>
        <style>
            body { font-family: sans-serif; }
            h1 { background: #1a1a2e; color: white; padding: 10px; }
            .badge { padding: 5px; border-radius: 5px; color: white; }
            .badge.low { background: #22c55e; }
            .badge.medium { background: #f59e0b; }
            .badge.high { background: #ef4444; }
            .badge.critical { background: #dc2626; }
        </style>
    </head>
    <body>
        <h1>NS-CTI Malware Analysis Report</h1>
        <p><strong>File:</strong> {{ file_name }}</p>
        <p><strong>SHA256:</strong> {{ sha256 }}</p>
        <p><strong>Generated At:</strong> {{ generated_at }}</p>
        <p><strong>Risk Level:</strong> <span class="badge {{ risk_level|lower }}">{{ risk_level }}</span></p>
        <p><strong>Analyst:</strong> {{ analyst }}</p>
    </body>
    </html>""")

    html_content = template.render(
        file_name=static_data.get("file_name", "Unknown"),
        sha256=static_data.get("sha256", "Unknown"),
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
        risk_level=groq_data.get("risk_level", "LOW"),
        analyst=analyst_name,
    )

    # Save PDF
    pdf_path = REPORTS_OUTPUT_PATH / f"{report_id}.pdf"
    HTML(string=html_content).write_pdf(pdf_path)

    # Save JSON
    json_path = REPORTS_OUTPUT_PATH / f"{report_id}.json"
    with open(json_path, "w") as f:
        json.dump(result_data, f, indent=4)

    return {
        "report_id": report_id,
        "pdf_path": str(pdf_path),
        "json_path": str(json_path),
        "ioc_path": str(ioc_path),
    }
