from typing import Any

from pydantic import BaseModel, Field


class RuntimeInvokeRequest(BaseModel):
    execution_id: str
    trace_id: str
    agent_id: str
    input: str
    session_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0


class RuntimeInvokeResponse(BaseModel):
    output: str
    model: str
    usage: Usage

