import pytest

from app.analysis import analyze
from app.analyzers.content import analyze_content, html_to_text
from app.models import EmailAnalysisRequest, Verdict

DMARC_PASS = "mx.google.com; dkim=pass; spf=pass; dmarc=pass header.from={domain}"


def ids(subject: str = "", body: str = "", html: str = "") -> set[str]:
    email = EmailAnalysisRequest(sender="x@example.com", subject=subject, body_text=body, body_html=html)
    return {f.id for f in analyze_content(email)}


# ---------- legitimate emails stay clean ----------


@pytest.mark.parametrize(
    "subject, body",
    [
        ("Your receipt", "Thank you for your payment of $25.00. Your order will ship soon."),
        ("Summer sale", "Big discounts on shoes. Sale ends today, don't miss out!"),
        ("Re: report", "See attached. This email is confidential and intended only for the recipient."),
        ("Welcome!", "Please confirm your email address to finish signing up."),
        ("Password changed", "Your password was changed. If this was you, no action is needed."),
        ("Meeting notes", "Thanks everyone, the insurgent marketing idea was great."),
        ("קבצים", "היי, תעבירי לי בבקשה את הקובץ של המצגת עד מחר. תודה!"),
        ("קבלה", "תודה על התשלום. החשבונית מצורפת."),
    ],
)
def test_ordinary_emails_are_clean(subject, body):
    assert ids(subject, body) == set()


# ---------- detections ----------


def test_money_request():
    assert ids(body="Please process a wire transfer to the account below.") == {"content.money_request"}


def test_credential_request():
    assert ids(body="Click below to verify your account.") == {"content.credential_request"}


def test_urgency_in_subject():
    assert ids(subject="URGENT: action required") == {"content.urgency"}


def test_secrecy():
    assert ids(body="Please keep this confidential for now.") == {"content.secrecy"}


def test_hebrew_phrases():
    found = ids(
        subject="החשבון שלך הוגבל",
        body="יש לאמת את פרטיך כדי למנוע חסימה. נא לבצע העברה בנקאית בסודיות.",
    )
    assert found == {
        "content.urgency", "content.credential_request", "content.money_request", "content.secrecy",
    }


def test_curly_apostrophe_and_line_breaks_are_normalized():
    assert ids(body="Please don’t tell\nanyone about this.") == {"content.secrecy"}


def test_one_finding_per_group_with_examples():
    findings = analyze_content(EmailAnalysisRequest(
        sender="x@example.com", body_text="Urgent! Act now, immediately, within 24 hours. Final notice.",
    ))
    assert len(findings) == 1
    assert findings[0].detail.count('"') == 6  # at most 3 quoted examples


def test_falls_back_to_html_and_ignores_scripts():
    html = "<style>.urgent{}</style><script>var urgent=1</script><p>Please <b>verify your account</b></p>"
    assert ids(html=html) == {"content.credential_request"}
    assert "urgent" not in html_to_text(html)


# ---------- patterns, end to end ----------


def test_ceo_fraud_is_caught_even_with_passing_authentication():
    result = analyze(EmailAnalysisRequest(
        sender="Dana Levi <dana@acme-industries.com>",
        reply_to="dana.levi.ceo@gmail.com",
        subject="Urgent - wire transfer needed today",
        body_text="Please wire 48,000 USD to our new supplier and keep this confidential.",
        authentication_results=[DMARC_PASS.format(domain="acme-industries.com")],
    ))
    assert result.findings[0].id == "pattern.ceo_fraud"
    assert result.verdict == Verdict.MALICIOUS


def test_ceo_fraud_from_free_email():
    result = analyze(EmailAnalysisRequest(
        sender="Dana Levi <dana.levi.ceo@gmail.com>",
        subject="Quick favor",
        body_text="I need you to buy gift cards for a client immediately. Keep this between us.",
    ))
    assert "pattern.ceo_fraud" in {f.id for f in result.findings}


def test_money_request_alone_from_known_colleague_is_not_fraud():
    result = analyze(EmailAnalysisRequest(
        sender="Finance <finance@acme-industries.com>",
        subject="Supplier payment",
        body_text="The wire transfer to our supplier was completed.",
        authentication_results=[DMARC_PASS.format(domain="acme-industries.com")],
    ))
    assert "pattern.ceo_fraud" not in {f.id for f in result.findings}
    assert result.verdict == Verdict.SAFE


def test_credential_phishing_needs_a_suspicious_link():
    base = dict(sender="Support <help@example.com>", body_text="Please verify your account.")
    disguised = '<a href="https://evil.example/login">https://www.paypal.com</a>'
    honest = '<a href="https://example.com/account">Verify</a>'
    with_bad_link = analyze(EmailAnalysisRequest(**base, body_html=disguised))
    with_good_link = analyze(EmailAnalysisRequest(**base, body_html=honest))
    assert "pattern.credential_phishing" in {f.id for f in with_bad_link.findings}
    assert "pattern.credential_phishing" not in {f.id for f in with_good_link.findings}
