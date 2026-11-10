from datetime import datetime, timedelta, timezone

from app import rdap
from app.analysis import analyze
from app.analyzers.base import finding
from app.models import EmailAnalysisRequest, Severity, Verdict
from app.patterns import ATTACK_BONUS, detect_patterns

DMARC_PASS = "mx.google.com; dkim=pass; spf=pass; dmarc=pass header.from={domain}"


def f(id: str):
    return finding(id, "test", Severity.INFO, "t", "d")


def pattern_ids(*finding_ids: str) -> list[str]:
    return [p.id for p in detect_patterns([f(i) for i in finding_ids])]


def registered_days_ago(monkeypatch, days: int):
    date = datetime.now(timezone.utc) - timedelta(days=days)
    monkeypatch.setattr(rdap, "registration_date", lambda domain: date)


# ---------- engine rules ----------


def test_brand_on_new_domain_matches():
    assert pattern_ids("sender.brand_impersonation", "sender.new_domain") == [
        "pattern.brand_spoofing_new_domain"
    ]


def test_any_impersonation_signal_satisfies_the_group():
    assert pattern_ids("sender.punycode_domain", "sender.new_domain") == [
        "pattern.brand_spoofing_new_domain"
    ]


def test_single_signal_matches_nothing():
    assert pattern_ids("sender.new_domain") == []
    assert pattern_ids("sender.brand_impersonation") == []


def test_only_strongest_attack_pattern_gets_bonus():
    found = detect_patterns([f("sender.lookalike_domain"), f("sender.new_domain"), f("auth.dmarc_pass")])
    assert [p.points for p in found] == [ATTACK_BONUS, 0]


def test_reassuring_pattern_is_suppressed_by_attack_pattern():
    ids = pattern_ids("sender.brand_domain_match", "auth.dmarc_pass", "sender.lookalike_domain")
    assert "pattern.verified_brand" not in ids


# ---------- end to end ----------


def test_new_lookalike_paypal_domain_is_named_as_attack(monkeypatch):
    registered_days_ago(monkeypatch, 3)
    result = analyze(EmailAnalysisRequest(sender="Support <help@paypa1.com>"))
    assert result.findings[0].id == "pattern.brand_spoofing_new_domain"  # shown first
    assert result.verdict == Verdict.MALICIOUS


def test_new_startup_domain_triggers_no_pattern(monkeypatch):
    registered_days_ago(monkeypatch, 20)
    result = analyze(EmailAnalysisRequest(sender="Hello <team@brand-new-startup.io>"))
    assert not any(x.category == "attack pattern" for x in result.findings)


def test_attacker_owned_lookalike_with_passing_auth(monkeypatch):
    registered_days_ago(monkeypatch, 400)  # old enough: only the auth pattern applies
    result = analyze(EmailAnalysisRequest(
        sender="Billing <billing@paypal-security-center.com>",
        authentication_results=[DMARC_PASS.format(domain="paypal-security-center.com")],
    ))
    assert "pattern.attacker_owned_lookalike" in {x.id for x in result.findings}


def test_attacker_owned_lookalike_without_dmarc_record(monkeypatch):
    registered_days_ago(monkeypatch, 400)
    result = analyze(EmailAnalysisRequest(
        sender="Billing <billing@paypal-security-center.com>",
        authentication_results=["mx.google.com; spf=pass; dkim=pass"],
    ))
    assert "pattern.attacker_owned_lookalike" in {x.id for x in result.findings}


def test_brand_name_on_free_email_is_never_verified():
    result = analyze(EmailAnalysisRequest(
        sender="Microsoft Support <microsoft.help@outlook.com>",
        authentication_results=[DMARC_PASS.format(domain="outlook.com")],
    ))
    found = {x.id for x in result.findings}
    assert "pattern.verified_brand" not in found
    assert "sender.brand_impersonation" in found
    assert result.verdict == Verdict.SUSPICIOUS


def test_verified_brand_is_reassuring():
    result = analyze(EmailAnalysisRequest(
        sender="PayPal <service@paypal.com>",
        authentication_results=[DMARC_PASS.format(domain="paypal.com")],
    ))
    verified = next(x for x in result.findings if x.id == "pattern.verified_brand")
    assert verified.points < 0
    assert result.verdict == Verdict.SAFE
    assert result.score == 0  # clamped, never negative
