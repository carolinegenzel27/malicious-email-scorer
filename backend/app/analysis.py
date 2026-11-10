"""Analysis pipeline: runs every analyzer, then scores the combined findings."""

import logging

from app.analyzers.authentication import analyze_authentication
from app.analyzers.base import Analyzer, finding
from app.analyzers.domain_age import analyze_domain_age
from app.analyzers.sender import analyze_sender
from app.models import AnalysisResult, EmailAnalysisRequest, Finding, Severity
from app.patterns import detect_patterns
from app.scoring import score_findings

logger = logging.getLogger(__name__)

ANALYZERS: tuple[Analyzer, ...] = (
    analyze_authentication,
    analyze_sender,
    analyze_domain_age,
)


def analyze(email: EmailAnalysisRequest) -> AnalysisResult:
    findings: list[Finding] = []
    for analyzer in ANALYZERS:
        findings += _run_safely(analyzer, email)
    # Second pass: look at the findings together for known attack combinations.
    findings += detect_patterns(findings)
    return score_findings(findings)


def _run_safely(analyzer: Analyzer, email: EmailAnalysisRequest) -> list[Finding]:
    """One buggy analyzer must not take down the whole analysis.

    Crafted input that triggers an exception in one check still gets scored
    by all the others, and the user is told a check was skipped.
    """
    try:
        return analyzer(email)
    except Exception:
        # Log the stack trace only - never the email content.
        logger.exception("Analyzer %s failed", analyzer.__name__)
        return [
            finding(
                f"internal.{analyzer.__name__}_failed",
                "internal",
                Severity.INFO,
                "One check could not be completed",
                "Part of the analysis failed, so this result may be incomplete.",
            )
        ]
