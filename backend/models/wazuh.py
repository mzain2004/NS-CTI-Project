from pydantic import BaseModel, ConfigDict


class WazuhAlert(BaseModel):
    model_config = ConfigDict(extra='ignore')

    alert_id: str
    timestamp: str
    rule_id: str
    rule_description: str
    rule_level: int
    severity: str
    agent_id: str
    agent_name: str
    src_ip: str | None
    dst_ip: str | None
    mitre_technique: str | None
    mitre_tactic: str | None
    full_log: str
    groups: list[str]
