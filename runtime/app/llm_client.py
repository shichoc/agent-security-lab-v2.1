import os

import httpx


PROVIDER = os.getenv("LLM_PROVIDER", "mock")
BASE_URL = os.getenv("LLM_BASE_URL", "http://host.docker.internal:11434").rstrip("/")
API_KEY = os.getenv("LLM_API_KEY", "")
MODEL = os.getenv("LLM_MODEL", "qwen3")
TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))


async def complete(system_prompt: str, user_input: str, temperature: float) -> dict:
    if PROVIDER == "mock":
        return {
            "output": f"Mock response to: {user_input}",
            "model": "mock-llm",
            "usage": {
                "input_tokens": len(user_input.split()),
                "output_tokens": len(user_input.split()) + 3,
            },
        }

    if PROVIDER != "openai-compatible":
        raise ValueError(f"Unsupported LLM_PROVIDER: {PROVIDER}")

    if not API_KEY:
        raise ValueError("LLM_API_KEY is required when LLM_PROVIDER=openai-compatible")

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input},
        ],
        "temperature": temperature,
    }
    headers = {"Authorization": f"Bearer {API_KEY}"}
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        response = await client.post(
            f"{BASE_URL}/v1/chat/completions",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
        data = response.json()

    usage = data.get("usage", {})
    return {
        "output": data["choices"][0]["message"]["content"],
        "model": data.get("model", MODEL),
        "usage": {
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
        },
    }
