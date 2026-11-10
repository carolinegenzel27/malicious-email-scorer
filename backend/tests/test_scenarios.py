"""End-to-end scenarios: realistic emails through the full pipeline."""

from app.analysis import analyze
from app.analyzers.base import finding
from app.models import EmailAnalysisRequest, Severity, Verdict
from app.scoring import score_findings

PASS = "mx.google.com; dkim=pass; spf=pass; dmarc=pass header.from={domain}"


def test_legitimate_google_email_is_safe():
    result = analyze(EmailAnalysisRequest(
        sender="Google AI Studio <googleaistudio-noreply@google.com>",
        subject="Automatic spend cap applied",
        authentication_results=[PASS.format(domain="google.com")],
    ))
    assert result.verdict == Verdict.SAFE
    assert result.score == 0


def test_spoofed_paypal_is_malicious():
    # Display name says PayPal, domain is a look-alike, replies go to Gmail.
    result = analyze(EmailAnalysisRequest(
        sender="PayPal Security <alert@paypa1.com>",
        reply_to="paypal.helpdesk@gmail.com",
        subject="Your account has been limited",
        authentication_results=["mx.google.com; spf=none; dkim=none"],
    ))
    assert result.verdict == Verdict.MALICIOUS
    assert result.findings[0].points >= result.findings[-1].points  # sorted


def test_ceo_fraud_with_passing_auth_is_still_flagged():
    # Attacker owns their domain, so SPF/DKIM/DMARC all pass - but Reply-To
    # diverts the answer. Authentication alone is not enough.
    result = analyze(EmailAnalysisRequest(
        sender="Dana (CEO) <dana@company-mail.com>",
        reply_to="dana.ceo.private@gmail.com",
        authentication_results=[PASS.format(domain="company-mail.com")],
    ))
    assert any(f.id == "sender.reply_to_mismatch" for f in result.findings)
    assert result.score > 0


def test_critical_finding_forces_malicious():
    result = score_findings([finding("x", "links", Severity.CRITICAL, "t", "d")])
    assert result.verdict == Verdict.MALICIOUS


def test_score_is_capped_at_100():
    many = [finding(f"x{i}", "c", Severity.HIGH, "t", "d") for i in range(10)]
    assert score_findings(many).score == 100


def test_broken_analyzer_does_not_break_analysis(monkeypatch):
    import app.analysis as pipeline

    def boom(email):
        raise ValueError("crafted input")

    monkeypatch.setattr(pipeline, "ANALYZERS", (boom, pipeline.analyze_sender))
    result = pipeline.analyze(EmailAnalysisRequest(sender="PayPal <x@evil.com>"))
    found = {f.id for f in result.findings}
    assert "internal.boom_failed" in found
    assert "sender.brand_impersonation" in found
