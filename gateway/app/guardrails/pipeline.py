from .base import Detector, GuardrailResult


class GuardrailPipeline:
    def __init__(self, detectors: list[Detector]) -> None:
        self.detectors = detectors

    async def evaluate(self, content: str, direction: str) -> GuardrailResult:
        current = content
        redacted = content
        all_signals: list[str] = []
        all_detectors: list[str] = []
        highest_risk = 0.0
        decision = "allow"
        metadata: dict = {}

        for detector in self.detectors:
            result = await detector.evaluate(current, direction)
            redacted = result.redacted_content
            all_signals.extend(result.signals)
            all_detectors.extend(result.detectors)
            highest_risk = max(highest_risk, result.risk_score)
            metadata.update(result.metadata)
            if result.decision == "deny":
                decision = "deny"
                break
            if result.decision == "warn":
                decision = "warn"
            current = result.content

        return GuardrailResult(
            decision=decision,
            content=current if decision != "deny" else "",
            redacted_content=redacted,
            risk_score=highest_risk,
            signals=list(dict.fromkeys(all_signals)),
            detectors=list(dict.fromkeys(all_detectors)),
            metadata=metadata,
        )
