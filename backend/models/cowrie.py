from pydantic import BaseModel, ConfigDict


class CowrieSession(BaseModel):
    model_config = ConfigDict(extra='ignore')

    session_id: str
    timestamp: str
    src_ip: str
    src_port: int
    dst_port: int
    protocol: str
    username: str | None
    password: str | None
    commands: list[str]
    duration_seconds: int
    files_downloaded: list[str]
    country: str | None


class CowrieSample(BaseModel):
    model_config = ConfigDict(extra='ignore')

    sha256: str
    filename: str
    size: int
    downloaded_at: str
    src_ip: str
    url: str | None
    mime_type: str | None
    analyzed: bool
    analysis_id: str | None
