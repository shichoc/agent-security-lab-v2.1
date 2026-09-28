from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: str
    execution_id: str
    trace_id: str
    agent_id: str
    direction: str | None = None
    decision: str | None = None
    risk_score: float | None = None
    signals: list[str] = Field(default_factory=list)
    detectors: list[str] = Field(default_factory=list)
    content_hash: str | None = None
    content_length: int | None = None
    captured_content: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)

