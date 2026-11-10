"""Turns findings into a 0-100 score and a verdict.

Deliberately simple and transparent: the score is the sum of the findings'
points, capped at 100. Every point on the score can be traced to a reason the
user can read. A weighted ML model might be more accurate, but could not
explain itself - and explainability is the core of this product.
"""

from app.models import AnalysisResult, Finding, Severity, Verdict

SUSPICIOUS_THRESHOLD = 25  # e.g. one HIGH signal alone
MALICIOUS_THRESHOLD = 60  # e.g. two HIGH signals, or HIGH + MEDIUM + LOW


def score_findings(findings: list[Finding]) -> AnalysisResult:
    # Most serious first, so the add-on shows the strongest reasons on top.
    ordered = sorted(findings, key=lambda f: f.points, reverse=True)
    score = min(100, sum(f.points for f in ordered))

    if score >= MALICIOUS_THRESHOLD or any(f.severity == Severity.CRITICAL for f in ordered):
        verdict = Verdict.MALICIOUS
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.SAFE

    return AnalysisResult(
        score=score,
        verdict=verdict,
        summary=_summary(verdict, ordered),
        findings=ordered,
    )


def _summary(verdict: Verdict, ordered: list[Finding]) -> str:
    warnings = [f for f in ordered if f.points > 0]
    if not warnings:
        return "No warning signs found."
    top = warnings[0].title
    count = f"{len(warnings)} warning sign{'s' if len(warnings) > 1 else ''}"
    if verdict == Verdict.MALICIOUS:
        return f"High risk - do not click links or reply. {count}. Most serious: {top}."
    if verdict == Verdict.SUSPICIOUS:
        return f"Be careful with this email. {count}. Most serious: {top}."
    return f"Low risk. Minor note: {top}."
