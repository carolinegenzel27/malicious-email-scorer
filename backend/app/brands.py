"""Brands that phishing commonly impersonates, and the domains they really use.

Kept as plain data so it is easy to review and extend. Includes Israeli brands
since that is where this add-on is demoed. A production system would source
this from threat intelligence or let an admin configure it per organization.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    keywords: tuple[str, ...]  # matched as whole words in the display name
    domains: frozenset[str]  # registrable domains the brand legitimately sends from


def _brand(name: str, keywords: tuple[str, ...], domains: set[str]) -> Brand:
    return Brand(name, keywords, frozenset(domains))


BRANDS: tuple[Brand, ...] = (
    _brand("PayPal", ("paypal",), {"paypal.com"}),
    _brand(
        "Microsoft",
        ("microsoft", "office 365", "office365", "outlook", "onedrive", "sharepoint"),
        {"microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com",
         "office365.com", "sharepoint.com", "onedrive.com"},
    ),
    _brand("Apple", ("apple", "icloud", "itunes"), {"apple.com", "icloud.com"}),
    _brand(
        "Google",
        ("google",),
        {"google.com", "youtube.com", "googleusercontent.com", "withgoogle.com"},
    ),
    _brand("Amazon", ("amazon", "aws"), {"amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com"}),
    _brand("Netflix", ("netflix",), {"netflix.com"}),
    _brand("Facebook", ("facebook",), {"facebook.com", "facebookmail.com", "meta.com"}),
    _brand("Instagram", ("instagram",), {"instagram.com", "facebookmail.com"}),
    _brand("WhatsApp", ("whatsapp",), {"whatsapp.com"}),
    _brand("LinkedIn", ("linkedin",), {"linkedin.com"}),
    _brand("DocuSign", ("docusign",), {"docusign.com", "docusign.net"}),
    _brand("Dropbox", ("dropbox",), {"dropbox.com", "dropboxmail.com"}),
    _brand("DHL", ("dhl",), {"dhl.com", "dhl.de", "dhl.co.il"}),
    _brand("FedEx", ("fedex",), {"fedex.com"}),
    _brand("Coinbase", ("coinbase",), {"coinbase.com"}),
    _brand("Israel Post", ("israel post", "דואר ישראל"), {"israelpost.co.il"}),
    _brand("Bank Hapoalim", ("hapoalim", "בנק הפועלים"), {"bankhapoalim.co.il"}),
    _brand("Bank Leumi", ("leumi", "בנק לאומי"), {"leumi.co.il"}),
)
