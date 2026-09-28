import asyncio
import hashlib
import os
from pathlib import Path
from typing import Protocol

from ..guardrails.base import GuardrailResult
from .models import SecurityEvent


class EventSink(Protocol):
    async def emit(self, event: SecurityEvent) -> None: ...


class JsonlEventSink:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._lock = asyncio.Lock()

    async def emit(self, event: SecurityEvent) -> None:
        line = event.model_dump_json() + "\n"
        async with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(line)
                stream.flush()


def create_event_sink() -> JsonlEventSink:
    return JsonlEventSink(os.getenv("EVENT_FILE", "/data/security-events.jsonl"))


def content_hash(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def captured_content(content: str, result: GuardrailResult) -> str | None:
    mode = os.getenv("EVENT_CAPTURE_MODE", "redacted").lower()
    if mode == "metadata":
        return None
    if mode == "full" and not result.signals:
        return content
    return result.redacted_content

