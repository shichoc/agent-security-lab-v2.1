from typing import Any, Literal

from pydantic import BaseModel, Field


class InvokeRequest(BaseModel):
    input: str = Field(min_length=1, max_length=32_000)
    session_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0


class InvokeResponse(BaseModel):
    execution_id: str
    trace_id: str
    agent_id: str
    status: Literal["completed", "blocked"]
    output: str
    model: str
    usage: Usage


class RuntimeInvokeRequest(BaseModel):
    execution_id: str
    trace_id: str
    agent_id: str
    input: str
    session_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

