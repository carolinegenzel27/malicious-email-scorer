from datetime import datetime, timedelta, timezone

import pytest

from app import rdap
from app.analyzers.domain_age import analyze_domain_age, days_since
from app.models import EmailAnalysisRequest


def ids_for_age(monkeypatch, days_old: int | None) -> set[str]:
    date = None if days_old is None else datetime.now(timezone.utc) - timedelta(days=days_old)
    monkeypatch.setattr(rdap, "registration_date", lambda domain: date)
    email = EmailAnalysisRequest(sender="Support <help@some-domain.com>")
    return {f.id for f in analyze_domain_age(email)}


def severity_for_age(monkeypatch, days_old: int) -> str:
    date = datetime.now(timezone.utc) - timedelta(days=days_old)
    monkeypatch.setattr(rdap, "registration_date", lambda domain: date)
    email = EmailAnalysisRequest(sender="Support <help@some-domain.com>")
    return analyze_domain_age(email)[0].severity.value


def test_brand_new_domain_is_high_risk(monkeypatch):
    assert ids_for_age(monkeypatch, 3) == {"sender.new_domain"}
    assert severity_for_age(monkeypatch, 3) == "high"


def test_two_week_old_domain_is_medium_risk(monkeypatch):
    assert ids_for_age(monkeypatch, 14) == {"sender.new_domain"}
    assert severity_for_age(monkeypatch, 14) == "medium"


def test_free_email_is_not_looked_up(monkeypatch):
    def fail(domain):
        raise AssertionError("must not look up free-mail domains")

    monkeypatch.setattr(rdap, "registration_date", fail)
    assert analyze_domain_age(EmailAnalysisRequest(sender="x@gmail.com")) == []


def test_few_months_old_domain_is_low_risk(monkeypatch):
    assert ids_for_age(monkeypatch, 90) == {"sender.young_domain"}


def test_old_domain_is_reassuring(monkeypatch):
    assert ids_for_age(monkeypatch, 365 * 20) == {"sender.established_domain"}


def test_unknown_age_adds_no_points(monkeypatch):
    email = EmailAnalysisRequest(sender="Leumi <info@leumi.co.il>")
    findings = analyze_domain_age(email)
    assert [f.id for f in findings] == ["sender.domain_age_unknown"]
    assert findings[0].points == 0


def test_lookup_uses_registrable_domain(monkeypatch):
    asked = []
    monkeypatch.setattr(rdap, "registration_date", lambda domain: asked.append(domain))
    analyze_domain_age(EmailAnalysisRequest(sender="x@mail.news.paypal.com"))
    assert asked == ["paypal.com"]


@pytest.mark.parametrize(
    "domain",
    ["evil.com/../admin", "evil.com?x=1", "a b.com", "localhost", "", "-bad.com", "evil.com#frag"],
)
def test_crafted_domains_are_rejected_before_any_request(domain):
    assert not rdap.is_valid_domain(domain)


@pytest.mark.parametrize("domain", ["paypal.com", "mail.leumi.co.il", "xn--pypal-4ve.com"])
def test_normal_domains_are_valid(domain):
    assert rdap.is_valid_domain(domain)


def test_parse_registration_date():
    data = {"events": [
        {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"},
        {"eventAction": "registration", "eventDate": "1999-07-15T05:32:11Z"},
    ]}
    assert rdap.parse_registration_date(data).year == 1999


@pytest.mark.parametrize(
    "data",
    [None, [], {"events": "x"}, {"events": [{"eventAction": "registration", "eventDate": "garbage"}]}],
)
def test_parse_survives_malformed_responses(data):
    assert rdap.parse_registration_date(data) is None


def test_days_since_handles_naive_dates():
    now = datetime(2026, 1, 31, tzinfo=timezone.utc)
    assert days_since(datetime(2026, 1, 1), now=now) == 30
