import pytest

from app.analyzers.sender import analyze_sender
from app.emailparse import org_domain
from app.lookalike import edit_distance
from app.models import EmailAnalysisRequest, Severity


def run(sender: str, reply_to: str = ""):
    return analyze_sender(EmailAnalysisRequest(sender=sender, reply_to=reply_to))


def ids(sender: str, reply_to: str = "") -> set[str]:
    return {f.id for f in run(sender, reply_to)}


def warnings(sender: str) -> list[str]:
    return [f"{f.id} (+{f.points})" for f in run(sender) if f.points > 0]


# ---------- false positives: legitimate senders must stay clean ----------


@pytest.mark.parametrize(
    "domain",
    [
        # One letter away from a brand's ordinary-word domain (live, meta, apple, icloud)
        "line.me", "love.com", "lime.com", "beta.com", "mega.nz", "metal.com",
        "apply.com", "ample.com", "cloud.com", "officer.com",
        # Brand word inside an unrelated word
        "pineapple.com", "appleton.com", "applebees.com", "officedepot.com", "olivegarden.com",
        "metadata.io",
        # Popular senders and services
        "github.com", "slack.com", "zoom.us", "atlassian.net", "wix.com", "shopify.com", "ebay.com",
        "aliexpress.com", "booking.com", "airbnb.com", "uber.com", "wolt.com", "spotify.com", "x.com",
        "medium.com", "substack.com", "mailchimp.com", "sendgrid.net", "hubspot.com", "salesforce.com",
        "notion.so", "canva.com", "figma.com", "example.com",
        # Brand-owned secondary domains
        "googlegroups.com", "netflixtechblog.com", "amazonpay.in",
        # Israeli and country domains
        "ynet.co.il", "max.co.il", "isracard.co.il", "leumicard.co.il", "paypay.ne.jp",
    ],
)
def test_legitimate_domains_are_not_flagged(domain):
    assert warnings(f"Newsletter <news@{domain}>") == []


@pytest.mark.parametrize(
    "sender",
    [
        "PayPal <service@paypal.com>",
        "PayPal <service@mail.paypal.com>",
        "Google AI Studio <googleaistudio-noreply@google.com>",
        "Bank Leumi <info@leumi.co.il>",
        "Amazon <order@amazon.co.jp>",
        "Alice Cohen <alice@example.com>",
    ],
)
def test_legitimate_senders_are_clean(sender):
    assert warnings(sender) == []


def test_real_brand_domain_is_recognized():
    assert ids("PayPal <service@paypal.com>") == {"sender.brand_domain_match"}


# ---------- display name ----------


def test_brand_display_name_from_wrong_domain():
    assert ids("PayPal Support <alerts@secure-mail.xyz>") == {"sender.brand_impersonation"}


def test_brand_name_on_free_email_is_impersonation_not_verified():
    # Anyone can register microsoft.help@outlook.com.
    assert ids("Microsoft Support <microsoft.help@outlook.com>") == {"sender.brand_impersonation"}


def test_hebrew_brand_name():
    assert "sender.brand_impersonation" in ids("בנק הפועלים <service@secure-update.com>")


def test_hebrew_brand_name_with_brand_domain_is_merged():
    assert ids("בנק הפועלים <service@poalim-secure-update.com>") == {"sender.brand_in_domain"}


def test_brand_word_inside_other_word_is_not_matched():
    assert ids("Pineapple Farm <hi@pineapplefarm.com>") == set()


def test_display_name_with_different_address():
    assert "sender.name_contains_other_address" in ids('"security@paypal.com" <x@evil.com>')


def test_plain_free_email_sender_is_noted_without_points():
    findings = run("Dana <dana.cohen@gmail.com>")
    assert [f.id for f in findings] == ["sender.free_email"]
    assert findings[0].points == 0


# ---------- domain imitation ----------


@pytest.mark.parametrize(
    "domain",
    ["paypa1.com", "paypai.com", "paypall.com", "rnicrosoft.com", "mircosoft.com",
     "arnazon.com", "dropb0x.com", "app1e.com", "netflx.com", "gooogle.com", "paypa1-secure.com"],
)
def test_lookalike_domains(domain):
    assert ids(f"Support <help@{domain}>") == {"sender.lookalike_domain"}


@pytest.mark.parametrize(
    "domain",
    ["paypal-security-center.com", "paypalsupport.com", "apple-id.com", "dhl-tracking.com", "paypal.xyz"],
)
def test_brand_name_inside_domain(domain):
    assert ids(f"Support <help@{domain}>") == {"sender.brand_in_domain"}


def test_punycode_domain():
    assert "sender.punycode_domain" in ids("Support <help@xn--pypal-4ve.com>")


# ---------- no double counting ----------


def test_name_and_lookalike_for_same_brand_is_one_finding():
    findings = run("PayPal <alert@paypa1.com>")
    assert [f.id for f in findings] == ["sender.lookalike_domain"]
    # One finding, but at least as strong as the two separate signals were.
    assert findings[0].severity == Severity.CRITICAL
    assert "both the name and the domain" in findings[0].title


def test_name_and_brand_in_domain_merge_and_escalate():
    findings = run("PayPal Support <help@paypal-help-center.com>")
    assert [f.id for f in findings] == ["sender.brand_in_domain"]
    assert findings[0].severity == Severity.HIGH


def test_different_brands_are_reported_separately():
    assert ids("Netflix <billing@paypa1.com>") == {"sender.brand_impersonation", "sender.lookalike_domain"}


# ---------- reply-to and parsing ----------


def test_reply_to_other_domain():
    assert "sender.reply_to_mismatch" in ids("CEO <ceo@company.com>", reply_to="ceo.private@gmail.com")


def test_reply_to_same_org_is_fine():
    assert ids("Shop <orders@shop.com>", reply_to="support@help.shop.com") == set()


def test_malformed_sender():
    assert ids("not an address") == {"sender.invalid"}


def test_org_domain_handles_country_suffixes():
    assert org_domain("mail.leumi.co.il") == "leumi.co.il"
    assert org_domain("a.b.paypal.com") == "paypal.com"
    assert org_domain("paypay.ne.jp") == "paypay.ne.jp"


def testedit_distance():
    assert edit_distance("paypal", "paypa1") == 1
    assert edit_distance("google", "google") == 0
