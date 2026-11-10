import pytest

from app.analyzers.sender import _edit_distance, analyze_sender
from app.emailparse import org_domain
from app.models import EmailAnalysisRequest


def ids(sender: str, reply_to: str = "") -> set[str]:
    email = EmailAnalysisRequest(sender=sender, reply_to=reply_to)
    return {f.id for f in analyze_sender(email)}


@pytest.mark.parametrize(
    "sender",
    [
        "PayPal <service@paypal.com>",
        "PayPal <service@mail.paypal.com>",  # subdomain of the real domain
        "Google AI Studio <googleaistudio-noreply@google.com>",
        "Bank Leumi <info@leumi.co.il>",
        "Alice Cohen <alice@example.com>",
    ],
)
def test_legitimate_senders_are_clean(sender):
    assert ids(sender) == set()


def test_brand_display_name_from_wrong_domain():
    assert "sender.brand_impersonation" in ids("PayPal Support <alerts@secure-mail.xyz>")


def test_brand_display_name_from_freemail():
    assert "sender.brand_impersonation" in ids("Microsoft Account Team <msteam2024@gmail.com>")


def test_hebrew_brand_name():
    assert "sender.brand_impersonation" in ids("בנק הפועלים <service@poalim-update.com>")


def test_brand_word_inside_other_word_is_not_matched():
    assert "sender.brand_impersonation" not in ids("Pineapple Farm <hi@pineapplefarm.com>")


def test_display_name_with_different_address():
    assert "sender.name_contains_other_address" in ids('"security@paypal.com" <x@evil.com>')


@pytest.mark.parametrize("domain", ["paypa1.com", "paypai.com", "rnicrosoft.com", "arnazon.com", "dropb0x.com"])
def test_lookalike_domains(domain):
    assert "sender.lookalike_domain" in ids(f"Support <help@{domain}>")


def test_brand_name_inside_domain():
    assert "sender.brand_in_domain" in ids("Support <help@paypal-security-center.com>")


def test_punycode_domain():
    assert "sender.punycode_domain" in ids("Support <help@xn--pypal-4ve.com>")


def test_reply_to_other_domain():
    assert "sender.reply_to_mismatch" in ids("CEO <ceo@company.com>", reply_to="ceo.private@gmail.com")


def test_reply_to_same_org_is_fine():
    assert ids("Shop <orders@shop.com>", reply_to="support@help.shop.com") == set()


def test_malformed_sender():
    assert ids("not an address") == {"sender.invalid"}


def test_org_domain_handles_country_suffixes():
    assert org_domain("mail.leumi.co.il") == "leumi.co.il"
    assert org_domain("a.b.paypal.com") == "paypal.com"


def test_edit_distance():
    assert _edit_distance("paypal", "paypa1") == 1
    assert _edit_distance("google", "google") == 0
