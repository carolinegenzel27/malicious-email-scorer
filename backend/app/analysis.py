"""Analysis pipeline: runs the analyzers and turns findings into a verdict.

Placeholder for now - analyzers are added in the next steps.
"""

from app.models import AnalysisResult, EmailAnalysisRequest, Verdict


def analyze(email: EmailAnalysisRequest) -> AnalysisResult:
    return AnalysisResult(
        score=0,
        verdict=Verdict.SAFE,
        summary="Backend connected. No analyzers enabled yet.",
        findings=[],
    )
