from dataclasses import dataclass, field
from typing import Any, Literal, Protocol


Decision = Literal["allow", "warn", "deny"]


@dataclass
class GuardrailResult:
    decision: Decision
    content: str
    redacted_content: str
    risk_score: float = 0.0
    signals: list[str] = field(default_factory=list)
    detectors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class Detector(Protocol):
    name: str
    version: str

    async def evaluate(self, content: str, direction: str) -> GuardrailResult: ...
