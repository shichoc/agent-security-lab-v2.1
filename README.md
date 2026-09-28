# Agent Security Lab V2

V2 keeps V1's Gateway/Runtime boundary and adds credential guardrails, an
optional LLM-as-Judge, structured logs, and persistent security events.

## Start

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Gateway: `http://localhost:8082`  
Swagger: `http://localhost:8082/docs`

## Safe request

```powershell
$body = @{ input = "What is a strong password policy?" } | ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri http://localhost:8082/v1/agents/basic-agent/invoke `
  -ContentType application/json `
  -Body $body
```

## Blocked input

```powershell
$body = @{ input = "password=Secret123!" } | ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri http://localhost:8082/v1/agents/basic-agent/invoke `
  -ContentType application/json `
  -Body $body
```

The request returns HTTP 403 and never reaches the Runtime.

## Inspect logs and events

```powershell
docker compose logs -f gateway runtime
Get-Content .\data\security-events.jsonl -Wait
```

Detected credentials are replaced with `[REDACTED]` before an event is stored.
Event capture defaults to `redacted`; use `metadata` when request/response content
must not be retained.

## Tests

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```

The output-blocking scenario is covered by an automated test because the normal
mock LLM echoes safe input and therefore cannot naturally emit a new credential.

## Optional LLM-as-Judge

The Agent model and Judge model have independent configuration. The Judge is
disabled by default. To test it without an external model:

```dotenv
JUDGE_ENABLED=true
JUDGE_PROVIDER=mock
JUDGE_MODEL=security-judge-test
```

For a separate OpenAI-compatible Judge model:

```dotenv
JUDGE_ENABLED=true
JUDGE_PROVIDER=openai-compatible
JUDGE_BASE_URL=https://api.openai.com
JUDGE_MODEL=gpt-4o-mini
```

Set `LLM_API_KEY` and `JUDGE_API_KEY` independently in the local `.env`. Their
values and sources are controlled by the operator, not by the application.
When an OpenAI-compatible provider is enabled, the corresponding client checks
that its key is non-empty. The `.env` file is excluded by `.gitignore`.

The credential detector runs first. Inputs containing explicit credentials are
blocked locally and are never sent to the Judge. Judge decisions, model name,
prompt version, latency, and token usage are recorded as
`guardrail.judge.evaluated` security events.
