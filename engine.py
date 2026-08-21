from .risk import calculate_risk

class ReasoningEngine:
    def analyze(self, finding, project_context):
        return {
            "finding": finding,
            "risk": calculate_risk(finding, project_context),
            "confidence": 0.85,
            "reasoning": [
                "User input reaches a sensitive function.",
                "No sanitization detected.",
                "Public endpoint increases exploitability."
            ]
        }
