import json
import logging
from pathlib import Path

import httpx
import yaml
from fastapi import FastAPI, HTTPException

from .llm_client import complete
from .models import RuntimeInvokeRequest, RuntimeInvokeResponse


logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("agent-runtime")

app = FastAPI(title="Agent Runtime", version="0.2.0")
AGENT_DIR = Path(__file__).parent / "agents"


def log_event(event: str, **fields) -> None:
    logger.info(json.dumps({"service": "agent-runtime", "event": event, **fields}))


def load_agent(agent_id: str) -> dict:
    safe_id = Path(agent_id).name
    if safe_id != agent_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    path = AGENT_DIR / f"{safe_id}.yaml"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Agent not found")
    with path.open("r", encoding="utf-8") as stream:
        return yaml.safe_load(stream)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.2.0"}


@app.post("/internal/v1/invoke", response_model=RuntimeInvokeResponse)
async def invoke(request: RuntimeInvokeRequest) -> RuntimeInvokeResponse:
    agent = load_agent(request.agent_id)
    context = {
        "execution_id": request.execution_id,
        "trace_id": request.trace_id,
        "agent_id": request.agent_id,
    }
    log_event("llm.started", **context)
    try:
        result = await complete(
            system_prompt=agent["system_prompt"],
            user_input=request.input,
            temperature=float(agent.get("temperature", 0.2)),
        )
    except httpx.TimeoutException as exc:
        log_event("llm.failed", **context, reason="timeout")
        raise HTTPException(status_code=504, detail="LLM timed out") from exc
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        log_event("llm.failed", **context, reason="request_failed")
        raise HTTPException(status_code=502, detail="LLM request failed") from exc

    log_event("llm.completed", **context, model=result["model"])
    return RuntimeInvokeResponse(**result)

