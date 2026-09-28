import logging
import time
import uuid

import httpx
from fastapi import FastAPI, HTTPException

from .agent_client import invoke_runtime
from .events.models import SecurityEvent
from .events.sink import captured_content, content_hash, create_event_sink
from .guardrails.credential_detector import CredentialDetector
from .guardrails.llm_judge import LlmJudgeDetector, env_bool
from .guardrails.pipeline import GuardrailPipeline
from .logging_config import configure_logging, log_event
from .models import InvokeRequest, InvokeResponse, RuntimeInvokeRequest


configure_logging()
logger = logging.getLogger("agent-gateway")

app = FastAPI(title="Agent Gateway", version="0.2.0")


def create_guardrails() -> GuardrailPipeline:
    detectors = [CredentialDetector()]
    if env_bool("JUDGE_ENABLED"):
        detectors.append(LlmJudgeDetector())
    return GuardrailPipeline(detectors)


guardrails = create_guardrails()
event_sink = create_event_sink()

BLOCKED_OUTPUT = "The generated response was blocked by a security policy."


async def emit(event_type: str, execution_id: str, trace_id: str, agent_id: str, **fields) -> None:
    await event_sink.emit(
        SecurityEvent(
            event_type=event_type,
            execution_id=execution_id,
            trace_id=trace_id,
            agent_id=agent_id,
            **fields,
        )
    )


async def emit_judge_result(result, direction: str, context: dict) -> None:
    judge = result.metadata.get("llm_judge")
    if not judge:
        return
    await emit(
        "guardrail.judge.evaluated",
        **context,
        direction=direction,
        decision=result.decision,
        risk_score=result.risk_score,
        signals=result.signals,
        detectors=[detector for detector in result.detectors if detector.startswith("llm-judge:")],
        attributes=judge,
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "version": "0.2.0",
        "judge_enabled": str(env_bool("JUDGE_ENABLED")).lower(),
    }


@app.post("/v1/agents/{agent_id}/invoke", response_model=InvokeResponse)
async def invoke(agent_id: str, request: InvokeRequest) -> InvokeResponse:
    started = time.perf_counter()
    execution_id = str(uuid.uuid4())
    trace_id = str(uuid.uuid4())
    context = {"execution_id": execution_id, "trace_id": trace_id, "agent_id": agent_id}

    log_event(logger, logging.INFO, "request.received", **context)
    await emit("request.received", **context)

    input_result = await guardrails.evaluate(request.input, "input")
    await emit(
        "guardrail.input.evaluated",
        **context,
        direction="input",
        decision=input_result.decision,
        risk_score=input_result.risk_score,
        signals=input_result.signals,
        detectors=input_result.detectors,
        content_hash=content_hash(request.input),
        content_length=len(request.input),
        captured_content=captured_content(request.input, input_result),
    )
    await emit_judge_result(input_result, "input", context)

    if input_result.decision == "deny":
        await emit("request.blocked", **context, direction="input", decision="deny", signals=input_result.signals)
        log_event(
            logger,
            logging.WARNING,
            "request.blocked",
            **context,
            direction="input",
            signals=input_result.signals,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "code": "INPUT_GUARDRAIL_BLOCKED",
                "message": "The request was blocked by a security policy.",
                "execution_id": execution_id,
                "trace_id": trace_id,
            },
        )

    runtime_request = RuntimeInvokeRequest(
        **context,
        input=input_result.content,
        session_id=request.session_id,
        metadata=request.metadata,
    )

    await emit("agent.started", **context)
    log_event(logger, logging.INFO, "agent.started", **context)
    try:
        runtime_result = await invoke_runtime(runtime_request)
    except httpx.TimeoutException as exc:
        await emit("execution.failed", **context, attributes={"reason": "runtime_timeout"})
        raise HTTPException(status_code=504, detail="Agent runtime timed out") from exc
    except httpx.HTTPStatusError as exc:
        status = 404 if exc.response.status_code == 404 else 502
        await emit(
            "execution.failed",
            **context,
            attributes={"reason": "runtime_error", "runtime_status": exc.response.status_code},
        )
        raise HTTPException(status_code=status, detail="Agent runtime failed") from exc
    except httpx.RequestError as exc:
        await emit("execution.failed", **context, attributes={"reason": "runtime_unavailable"})
        raise HTTPException(status_code=503, detail="Agent runtime unavailable") from exc

    await emit(
        "agent.completed",
        **context,
        attributes={"model": runtime_result["model"], "usage": runtime_result["usage"]},
    )

    output = runtime_result["output"]
    output_result = await guardrails.evaluate(output, "output")
    await emit(
        "guardrail.output.evaluated",
        **context,
        direction="output",
        decision=output_result.decision,
        risk_score=output_result.risk_score,
        signals=output_result.signals,
        detectors=output_result.detectors,
        content_hash=content_hash(output),
        content_length=len(output),
        captured_content=captured_content(output, output_result),
    )
    await emit_judge_result(output_result, "output", context)

    if output_result.decision == "deny":
        await emit("response.blocked", **context, direction="output", decision="deny", signals=output_result.signals)
        log_event(
            logger,
            logging.WARNING,
            "response.blocked",
            **context,
            direction="output",
            signals=output_result.signals,
        )
        return InvokeResponse(
            **context,
            status="blocked",
            output=BLOCKED_OUTPUT,
            model=runtime_result["model"],
            usage=runtime_result["usage"],
        )

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    await emit("response.returned", **context, attributes={"duration_ms": duration_ms})
    log_event(logger, logging.INFO, "response.returned", **context, duration_ms=duration_ms)
    return InvokeResponse(
        **context,
        status="completed",
        output=output_result.content,
        model=runtime_result["model"],
        usage=runtime_result["usage"],
    )
