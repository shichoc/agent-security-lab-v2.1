import re

from .base import GuardrailResult


class CredentialDetector:
    name = "credential-detector"
    version = "1.0.0"

    _rules = (
        (
            "credential.password",
            re.compile(
                r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*(?P<secret>[^\s,;]+)"
                r"|\bmy\s+(?:password|passwd|pwd)\s+is\s+(?P<natural>[^\s,;]+)"
            ),
        ),
        (
            "credential.api_key",
            re.compile(
                r"(?i)\b(?:api[_ -]?key|access[_ -]?token|secret[_ -]?key)\s*[:=]\s*"
                r"(?P<secret>[^\s,;]+)"
            ),
        ),
        (
            "credential.bearer_token",
            re.compile(r"(?i)\b(?:authorization\s*:\s*)?bearer\s+(?P<secret>[A-Za-z0-9._~+/-]{4,}=*)"),
        ),
        (
            "credential.openai_key",
            re.compile(r"\b(?P<secret>sk-[A-Za-z0-9_-]{8,})\b"),
        ),
    )

    async def evaluate(self, content: str, direction: str) -> GuardrailResult:
        redacted = content
        signals: list[str] = []

        for signal, pattern in self._rules:
            if pattern.search(content):
                signals.append(signal)
                redacted = pattern.sub(lambda match: self._redact_match(match), redacted)

        unique_signals = list(dict.fromkeys(signals))
        if unique_signals:
            return GuardrailResult(
                decision="deny",
                content="",
                redacted_content=redacted,
                risk_score=1.0,
                signals=unique_signals,
                detectors=[f"{self.name}:{self.version}"],
            )

        return GuardrailResult(
            decision="allow",
            content=content,
            redacted_content=content,
            detectors=[f"{self.name}:{self.version}"],
        )

    @staticmethod
    def _redact_match(match: re.Match[str]) -> str:
        text = match.group(0)
        secret = match.groupdict().get("secret") or match.groupdict().get("natural")
        if not secret:
            return "[REDACTED]"
        return text.replace(secret, "[REDACTED]")
