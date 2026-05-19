from pydantic import BaseModel, Field
from typing import List, Dict, Any
from uuid import UUID

class AgentState(BaseModel):
    task_id: UUID
    history: List[str] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    is_complete: bool = False
    current_risk_score: float = 0.0
