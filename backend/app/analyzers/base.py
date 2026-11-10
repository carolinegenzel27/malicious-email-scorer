"""Shared building blocks for analyzers.

An analyzer is a plain function: EmailAnalysisRequest -> list[Finding].
Analyzers are independent of each other, so adding one never changes another.
"""

from collections.abc import Callable

from app.models import EmailAnalysisRequest, Finding, Severity

Analyzer = Callable[[EmailAnalysisRequest], list[Finding]]

# One fixed weight per severity keeps scoring predictable and explainable:
# "a high-severity signal is worth 30 points", regardless of which analyzer
# raised it. Tuned so that one HIGH + one MEDIUM signal = "malicious".
SEVERITY_POINTS = {
    Severity.INFO: 0,
    Severity.LOW: 8,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 60,
}


def finding(id: str, category: str, severity: Severity, title: str, detail: str) -> Finding:
    return Finding(
        id=id,
        category=category,
        severity=severity,
        title=title,
        detail=detail,
        points=SEVERITY_POINTS[severity],
    )
