"""Links: is a link trying to deceive the user about where it leads?

Static analysis of the URL text only - links are never visited (see app.links).

One finding per type of problem, not per link: ten disguised links are one
finding with examples, so the score and the card are not flooded.
"""

import re
from collections.abc import Callable

from app.analyzers.base import finding
from app.brands import BRANDS
from app.emailparse import clip, org_domain, parse_address
from app.links import Link, extract_links
from app.lookalike import Kind, find_imitation
from app.models import EmailAnalysisRequest, Finding, Severity

CATEGORY = "links"
MAX_EXAMPLES = 3

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly",
})

# Legitimate services that rewrite every link through their own domain (email
# marketing click tracking, corporate link protection). Text showing one site
# while the link goes through these is normal, not a disguise.
CLICK_TRACKERS = frozenset({
    "sendgrid.net", "list-manage.com", "mandrillapp.com", "hubspotlinks.com",
    "sparkpostmail.com", "mailgun.org", "exacttarget.com", "rs6.net", "createsend.com",
    "outlook.com",  # *.safelinks.protection.outlook.com
    "urldefense.com", "mimecast.com",
    # Deliberately NOT google.com: attackers host phishing pages on Google
    # Sites / Forms precisely because the domain looks trustworthy.
})

# "invoice.pdf" looks like a domain but is a file name.
_FILE_EXTENSIONS = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
    "jpg", "jpeg", "png", "gif", "zip", "rar", "html", "htm",
})
_URL_LIKE_TEXT_RE = re.compile(
    r"^(?P<scheme>https?://)?(?P<host>(?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$"
)


def analyze_links(email: EmailAnalysisRequest) -> list[Finding]:
    links = extract_links(email.body_html, email.body_text)
    if not links:
        return []

    sender = parse_address(email.sender)
    sender_org = sender.org_domain if sender else ""

    mismatched: list[str] = []
    ip_links: list[str] = []
    lookalike: dict[str, list[str]] = {}  # brand name -> examples
    brand_in_domain: dict[str, list[str]] = {}
    punycode: list[str] = []
    shortened: list[str] = []

    for link in links:
        if shown := _disguised_destination(link):
            mismatched.append(f'shows "{clip(shown, 60)}" but leads to {clip(link.host, 60)}')
        if link.is_ip:
            ip_links.append(clip(link.url, 80))
            continue

        link_org = org_domain(link.host)
        if any(label.startswith("xn--") for label in link.host.split(".")):
            punycode.append(clip(link.host, 80))
        if link_org in URL_SHORTENERS or link.host in URL_SHORTENERS:
            shortened.append(clip(link.url, 80))
        # The sender's own domain is already judged by the sender analyzer.
        if link_org != sender_org and (imitation := find_imitation(link_org)):
            bucket = lookalike if imitation.kind == Kind.LOOKALIKE else brand_in_domain
            bucket.setdefault(imitation.brand.name, []).append(clip(link.host, 80))

    findings: list[Finding] = []
    _add(findings, mismatched, lambda: finding(
        "links.text_mismatch", CATEGORY, Severity.HIGH,
        "Link text shows a different address than where it leads",
        "A link " + _examples(mismatched) + ".",
    ))
    _add(findings, ip_links, lambda: finding(
        "links.ip_address", CATEGORY, Severity.HIGH,
        "Link points to a raw IP address",
        "Legitimate services use domain names. Link: " + _examples(ip_links) + ".",
    ))
    for brand, hosts in lookalike.items():
        findings.append(finding(
            "links.lookalike_domain", CATEGORY, Severity.HIGH,
            f"Link points to a domain imitating {brand}",
            f"{_examples(hosts)} looks like {brand}, but is not one of its domains.",
        ))
    for brand, hosts in brand_in_domain.items():
        findings.append(finding(
            "links.brand_in_domain", CATEGORY, Severity.MEDIUM,
            f"Link uses the {brand} name on a domain {brand} does not own",
            f"{_examples(hosts)} contains the {brand} name.",
        ))
    _add(findings, punycode, lambda: finding(
        "links.punycode_domain", CATEGORY, Severity.MEDIUM,
        "Link uses look-alike international characters",
        f"{_examples(punycode)} is an encoded international domain.",
    ))
    _add(findings, shortened, lambda: finding(
        "links.shortener", CATEGORY, Severity.LOW,
        "Link destination is hidden by a URL shortener",
        f"{_examples(shortened)} hides where it really leads.",
    ))
    return findings


def _disguised_destination(link: Link) -> str | None:
    """If the visible text is itself an address of a DIFFERENT site, return it."""
    text = link.text.strip().lower()
    match = _URL_LIKE_TEXT_RE.match(text)
    if not match:
        return None  # "Click here", "View invoice" - not an address
    shown_host = match.group("host").removeprefix("www.")
    if not match.group("scheme") and shown_host.rsplit(".", 1)[-1] in _FILE_EXTENSIONS:
        return None  # "invoice.pdf"
    shown_org, real_org = org_domain(shown_host), org_domain(link.host)
    if shown_org == real_org or real_org in CLICK_TRACKERS or _same_brand(shown_org, real_org):
        return None
    return text


def _same_brand(a: str, b: str) -> bool:
    return any(a in brand.domains and b in brand.domains for brand in BRANDS)


def _examples(items: list[str]) -> str:
    unique = list(dict.fromkeys(items))
    shown = ", ".join(unique[:MAX_EXAMPLES])
    extra = len(unique) - MAX_EXAMPLES
    return shown + (f" (and {extra} more)" if extra > 0 else "")


def _add(findings: list[Finding], items: list[str], build: Callable[[], Finding]) -> None:
    if items:
        findings.append(build())
