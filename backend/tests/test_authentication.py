from app.analyzers.authentication import analyze_authentication, parse_authentication_results
from app.models import EmailAnalysisRequest

GMAIL_PASS = (
    "mx.google.com; dkim=pass header.i=@paypal.com header.s=pp; "
    "spf=pass (google.com: domain of x@paypal.com designates 1.2.3.4) smtp.mailfrom=x@paypal.com; "
    "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com"
)


def ids(auth_headers: list[str]) -> set[str]:
    email = EmailAnalysisRequest(sender="a@b.com", authentication_results=auth_headers)
    return {f.id for f in analyze_authentication(email)}


def test_dmarc_pass_is_reassuring():
    assert ids([GMAIL_PASS]) == {"auth.dmarc_pass"}


def test_dmarc_fail_is_high_risk():
    header = "mx.google.com; spf=fail smtp.mailfrom=evil.com; dmarc=fail (p=NONE) header.from=paypal.com"
    assert ids([header]) == {"auth.dmarc_fail"}


def test_forged_header_from_attacker_is_ignored():
    # An attacker can add their own "everything passed" header. Only Gmail's counts.
    forged = "evil-server.com; spf=pass; dkim=pass; dmarc=pass header.from=paypal.com"
    assert parse_authentication_results([forged]) is None
    assert ids([forged]) == {"auth.no_trusted_results"}


def test_no_dmarc_falls_back_to_spf_and_dkim():
    header = "mx.google.com; spf=softfail smtp.mailfrom=x.com; dkim=none"
    assert ids([header]) == {"auth.spf_weak", "auth.dkim_missing"}


def test_one_passing_dkim_signature_is_enough():
    header = "mx.google.com; dkim=fail header.i=@a.com; dkim=pass header.i=@b.com; spf=pass"
    results = parse_authentication_results([header])
    assert results.dkim == "pass"
