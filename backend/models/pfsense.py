from pydantic import BaseModel, ConfigDict


class PfSenseRule(BaseModel):
    model_config = ConfigDict(extra='ignore')

    rule_id: str
    action: str
    protocol: str
    src_ip: str
    dst_ip: str | None
    dst_port: int | None
    description: str
    created_at: str
    created_by: str
    active: bool


class BlockRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')

    ip: str
    reason: str
    analysis_id: str | None
    duration_hours: int | None


class BlockResponse(BaseModel):
    model_config = ConfigDict(extra='ignore')

    success: bool
    rule_id: str | None
    message: str
