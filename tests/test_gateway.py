import json

from fastapi.testclient import TestClient

from gateway.app import main
from gateway.app.events.sink import JsonlEventSink


async def safe_runtime(request):
    return {
        "output": f"Safe response to: {request.input}",
        "model": "mock-llm",
        "usage": {"input_tokens": 1, "output_tokens": 4},
    }


async def unsafe_runtime(request):
    return {
        "output": "The password=ServerSecret123!",
        "model": "mock-llm",
        "usage": {"input_tokens": 1, "output_tokens": 4},
    }


def configure_test(monkeypatch, tmp_path, runtime):
    event_path = tmp_path / "events.jsonl"
    monkeypatch.setattr(main, "event_sink", JsonlEventSink(str(event_path)))
    monkeypatch.setattr(main, "invoke_runtime", runtime)
    monkeypatch.setenv("EVENT_CAPTURE_MODE", "redacted")
    return TestClient(main.app), event_path


def read_events(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_allows_safe_request(monkeypatch, tmp_path):
    client, event_path = configure_test(monkeypatch, tmp_path, safe_runtime)
    response = client.post("/v1/agents/basic-agent/invoke", json={"input": "hello"})
    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert any(event["event_type"] == "response.returned" for event in read_events(event_path))


def test_blocks_input_and_does_not_call_runtime(monkeypatch, tmp_path):
    called = False

    async def should_not_run(request):
        nonlocal called
        called = True
        return await safe_runtime(request)

    client, event_path = configure_test(monkeypatch, tmp_path, should_not_run)
    response = client.post(
        "/v1/agents/basic-agent/invoke",
        json={"input": "password=InputSecret123!"},
    )
    assert response.status_code == 403
    assert not called
    raw_events = event_path.read_text(encoding="utf-8")
    assert "InputSecret123" not in raw_events
    assert "[REDACTED]" in raw_events


def test_blocks_output_and_never_returns_secret(monkeypatch, tmp_path):
    client, event_path = configure_test(monkeypatch, tmp_path, unsafe_runtime)
    response = client.post("/v1/agents/basic-agent/invoke", json={"input": "safe input"})
    assert response.status_code == 200
    assert response.json()["status"] == "blocked"
    assert "ServerSecret123" not in response.text
    raw_events = event_path.read_text(encoding="utf-8")
    assert "ServerSecret123" not in raw_events
    assert any(event["event_type"] == "response.blocked" for event in read_events(event_path))

