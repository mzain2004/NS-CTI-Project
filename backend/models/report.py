from pydantic import BaseModel, ConfigDict


class ReportMetadata(BaseModel):
    model_config = ConfigDict(extra='ignore')

    report_id: str
    analysis_id: str
    file_name: str
    sha256: str
    generated_at: str
    risk_level: str
    analyst: str


class ReportGenerateRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')

    analysis_id: str
    analyst: str
    formats: list[str]


class ReportExport(BaseModel):
    model_config = ConfigDict(extra='ignore')

    report_id: str
    format: str
    download_url: str
