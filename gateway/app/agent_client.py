import os

import httpx

from .models import RuntimeInvokeRequest


RUNTIME_BASE_URL = os.getenv("RUNTIME_BASE_URL", "http://runtime:8081").rstrip("/")
RUNTIME_TIMEOUT_SECONDS = float(os.getenv("RUNTIME_TIMEOUT_SECONDS", "75"))


async def invoke_runtime(request: RuntimeInvokeRequest) -> dict:
    async with httpx.AsyncClient(timeout=RUNTIME_TIMEOUT_SECONDS) as client:
        response = await client.post(
            f"{RUNTIME_BASE_URL}/internal/v1/invoke",
            json=request.model_dump(),
        )
        response.raise_for_status()
        return response.json()

