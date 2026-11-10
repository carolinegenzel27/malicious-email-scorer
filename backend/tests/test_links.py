import pytest

from app.analysis import analyze
from app.analyzers.links import analyze_links
from app.links import MAX_LINKS, extract_links
from app.models import EmailAnalysisRequest, Verdict


def a(href: str, text: str) -> str:
    return f'<a href="{href}">{text}</a>'


def ids(html: str = "", text: str = "", sender: str = "News <news@example.com>") -> set[str]:
    email = EmailAnalysisRequest(sender=sender, body_html=html, body_text=text)
    return {f.id for f in analyze_links(email)}


# ---------- extraction ----------


def test_extracts_anchors_and_bare_urls():
    links = extract_links(a("https://site.com/x", "Click <b>here</b>"), "see https://other.com/y.")
    assert [(link.host, link.text) for link in links] == [("site.com", "Click here"), ("other.com", "")]


def test_ignores_non_web_links():
    html = a("mailto:x@y.com", "mail") + a("tel:123", "call") + a("#top", "top") + a("/relative", "r")
    assert extract_links(html, "") == []


def test_survives_malformed_html_and_urls():
    html = '<a href="http://[broken/x">a</a><div><a href="https://ok.com">unclosed'
    assert [link.host for link in extract_links(html, "")] == ["ok.com"]


def test_link_count_is_capped():
    html = "".join(a(f"https://site{i}.com", "x") for i in range(MAX_LINKS + 50))
    assert len(extract_links(html, "")) == MAX_LINKS


# ---------- legitimate emails stay clean ----------


def test_typical_newsletter_is_clean():
    html = (
        a("https://shop.com/view", "View in browser")
        + a("https://www.shop.com/sale", "www.shop.com")
        + a("https://u123.ct.sendgrid.net/ls/click?x=1", "shop.com/deals")  # click tracking
        + a("https://www.facebook.com/shop", "facebook.com/shop")
        + a("https://drive.google.com/file/1", "invoice.pdf")
        + a("mailto:unsubscribe@shop.com", "Unsubscribe")
    )
    assert ids(html, sender="Shop <news@shop.com>") == set()


@pytest.mark.parametrize(
    "host", ["love.com", "mega.nz", "cloud.com", "apply.com", "pineapple.com", "github.com"]
)
def test_links_to_legitimate_domains_are_clean(host):
    assert ids(a(f"https://{host}/page", "Read more")) == set()


def test_same_brand_different_domain_is_not_a_mismatch():
    assert ids(a("https://www.facebookmail.com/n", "facebook.com")) == set()


# ---------- detections ----------


def test_text_shows_one_site_but_link_goes_elsewhere():
    assert ids(a("https://evil.example/login", "https://www.paypal.com/signin")) == {"links.text_mismatch"}


def test_phishing_page_on_google_sites_is_a_mismatch():
    assert ids(a("https://sites.google.com/view/paypal-login", "paypal.com")) == {"links.text_mismatch"}


def test_raw_ip_address():
    assert ids(text="Login at http://185.23.4.1/login now") == {"links.ip_address"}


def test_lookalike_link_domain():
    assert ids(a("https://paypa1-login.com/x", "Sign in")) == {"links.lookalike_domain"}


def test_brand_name_in_link_domain():
    assert ids(a("https://paypal-verify-account.com/x", "Verify")) == {"links.brand_in_domain"}


def test_punycode_link():
    assert ids(a("https://xn--pypal-4ve.com/x", "Open")) == {"links.punycode_domain"}


def test_url_shortener():
    assert ids(text="Track your parcel: https://bit.ly/3xYz") == {"links.shortener"}


# ---------- no duplicates ----------


def test_many_bad_links_are_one_finding():
    html = "".join(a(f"https://evil{i}.example/x", "paypal.com") for i in range(10))
    findings = analyze_links(EmailAnalysisRequest(sender="x@example.com", body_html=html))
    assert len(findings) == 1
    assert "(and 7 more)" in findings[0].detail


def test_sender_domain_is_not_judged_twice():
    # paypa1.com is already reported by the sender analyzer.
    assert ids(a("https://paypa1.com/x", "Sign in"), sender="PayPal <x@paypa1.com>") == set()


# ---------- end to end ----------


def test_disguised_link_to_fake_paypal_raises_verdict():
    result = analyze(EmailAnalysisRequest(
        sender="PayPal <service@paypa1.com>",
        body_html=a("https://paypa1-secure.example/login", "https://www.paypal.com/signin"),
    ))
    found = {f.id for f in result.findings}
    assert {"links.text_mismatch", "links.lookalike_domain"} <= found
    assert result.verdict == Verdict.MALICIOUS
