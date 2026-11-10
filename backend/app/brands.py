"""Reference data: impersonated brands and free email providers.

Kept as plain data so it is easy to review and extend. Includes Israeli brands
since that is where this add-on is demoed. A production system would source
this from threat intelligence or let an admin configure it per organization.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    # Matched as whole words in the sender's display name.
    keywords: tuple[str, ...]
    # Registrable domains the brand legitimately sends from.
    domains: frozenset[str]
    # Distinctive names that look-alike domains are compared against.
    # Ordinary words a brand happens to own (live.com, meta.com, office.com)
    # are deliberately NOT here: love.com or mega.nz are not attacks.
    lookalike_targets: tuple[str, ...]


def _brand(name: str, keywords: tuple[str, ...], domains: set[str], targets: tuple[str, ...]) -> Brand:
    return Brand(name, keywords, frozenset(domains), targets)


BRANDS: tuple[Brand, ...] = (
    _brand("PayPal", ("paypal",), {"paypal.com"}, ("paypal",)),
    _brand(
        "Microsoft",
        ("microsoft", "office 365", "office365", "outlook", "onedrive", "sharepoint"),
        {"microsoft.com", "office.com", "microsoftonline.com", "office365.com",
         "sharepoint.com", "onedrive.com"},
        ("microsoft", "office365", "onedrive", "sharepoint"),
    ),
    _brand("Apple", ("apple", "icloud", "itunes"), {"apple.com"}, ("apple", "icloud", "itunes")),
    _brand(
        "Google",
        ("google",),
        {"google.com", "youtube.com", "googlegroups.com", "googleusercontent.com", "withgoogle.com"},
        ("google", "gmail"),
    ),
    _brand(
        "Amazon",
        ("amazon", "aws"),
        {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es",
         "amazon.ca", "amazon.co.jp", "amazon.in", "amazonpay.in", "amazonaws.com"},
        ("amazon",),
    ),
    _brand("Netflix", ("netflix",), {"netflix.com", "netflixtechblog.com"}, ("netflix",)),
    _brand("Facebook", ("facebook",), {"facebook.com", "facebookmail.com", "meta.com"}, ("facebook",)),
    _brand("Instagram", ("instagram",), {"instagram.com", "facebookmail.com"}, ("instagram",)),
    _brand("WhatsApp", ("whatsapp",), {"whatsapp.com"}, ("whatsapp",)),
    _brand("LinkedIn", ("linkedin",), {"linkedin.com"}, ("linkedin",)),
    _brand("DocuSign", ("docusign",), {"docusign.com", "docusign.net"}, ("docusign",)),
    _brand("Dropbox", ("dropbox",), {"dropbox.com", "dropboxmail.com"}, ("dropbox",)),
    _brand("DHL", ("dhl",), {"dhl.com", "dhl.de", "dhl.co.il"}, ("dhl",)),
    _brand("FedEx", ("fedex",), {"fedex.com"}, ("fedex",)),
    _brand("Coinbase", ("coinbase",), {"coinbase.com"}, ("coinbase",)),
    _brand("Israel Post", ("israel post", "דואר ישראל"), {"israelpost.co.il"}, ("israelpost",)),
    _brand(
        "Bank Hapoalim",
        ("hapoalim", "בנק הפועלים"),
        {"bankhapoalim.co.il"},
        ("bankhapoalim", "hapoalim", "poalim"),
    ),
    _brand("Bank Leumi", ("leumi", "בנק לאומי"), {"leumi.co.il"}, ("leumi",)),
)

# Anyone can register an address on these in a minute, so they say nothing
# about who the sender is - and never count as a brand's own domain.
FREE_EMAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com",
    "gmx.com", "mail.com", "yandex.com", "zoho.com", "walla.co.il",
})


def is_free_email(org_domain: str) -> bool:
    return org_domain in FREE_EMAIL_DOMAINS
