"""Sender identity: is the sender who they appear to be?

Users judge an email mostly by the display name ("PayPal"), not the address
behind it. These checks compare what the user SEES with what is REAL.

Each deception is reported once: if both the display name and the domain
imitate the same brand, that is one impersonation, not two findings.
"""

import re

from app.analyzers.base import finding
from app.brands import BRANDS, Brand, is_free_email
from app.emailparse import Address, clip, parse_address
from app.lookalike import Kind, find_imitation
from app.models import EmailAnalysisRequest, Finding, Severity

CATEGORY = "sender"

_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def analyze_sender(email: EmailAnalysisRequest) -> list[Finding]:
    sender = parse_address(email.sender)
    if sender is None:
        return [
            finding(
                "sender.invalid", CATEGORY, Severity.MEDIUM,
                "Sender address is missing or malformed",
                f"Could not read a valid email address from: {clip(email.sender, 100)!r}",
            )
        ]

    findings: list[Finding] = []
    name_brand = _brand_in_display_name(sender)
    imitation = _domain_imitation(sender)  # (brand, finding) or None

    if name_brand and _is_brand_domain(sender, name_brand):
        findings.append(finding(
            "sender.brand_domain_match", CATEGORY, Severity.INFO,
            f"Sender address matches {name_brand.name}'s real domain",
            f"{clip(sender.domain, 80)} is a domain {name_brand.name} really uses.",
        ))
    elif name_brand and imitation and imitation[0] == name_brand:
        # Name AND domain imitate the same brand: one deception, one finding.
        findings.append(_merged_impersonation(sender, *imitation))
        imitation = None
    elif name_brand:
        findings.append(finding(
            "sender.brand_impersonation", CATEGORY, Severity.HIGH,
            f"Display name claims to be {name_brand.name}, but the address is not",
            f'Shown as "{clip(sender.display_name, 80)}", but sent from '
            f"{clip(sender.domain, 80)}. {name_brand.name} sends from "
            f"{', '.join(sorted(name_brand.domains))}.",
        ))
    elif is_free_email(sender.org_domain):
        findings.append(finding(
            "sender.free_email", CATEGORY, Severity.INFO,
            "Sent from a free email address",
            f"Anyone can create an address on {sender.org_domain}, so the address "
            "alone says nothing about who the sender is.",
        ))

    if imitation:
        findings.append(imitation[1])
    findings += _punycode_domain(sender)
    findings += _display_name_has_other_address(sender)
    findings += _reply_to_mismatch(sender, email.reply_to)
    return findings


# ---------- display name ----------


def _brand_in_display_name(sender: Address) -> Brand | None:
    name = sender.display_name.lower()
    for brand in BRANDS:
        if any(re.search(rf"(?<!\w){re.escape(k)}(?!\w)", name) for k in brand.keywords):
            return brand
    return None


def _is_brand_domain(sender: Address, brand: Brand) -> bool:
    # A free-mail address is never a brand's own: "Microsoft" <x@outlook.com>
    # can be registered by anyone.
    return sender.org_domain in brand.domains and not is_free_email(sender.org_domain)


def _display_name_has_other_address(sender: Address) -> list[Finding]:
    """'security@paypal.com' <attacker@evil.com> - the name looks like an address."""
    match = _EMAIL_IN_TEXT_RE.search(sender.display_name)
    if match and match.group(0).lower() != sender.email:
        return [finding(
            "sender.name_contains_other_address", CATEGORY, Severity.HIGH,
            "Display name shows a different email address",
            f"The name shows {clip(match.group(0), 80)}, but the real sender is "
            f"{clip(sender.email, 80)}.",
        )]
    return []


# ---------- domain ----------


def _domain_imitation(sender: Address) -> tuple[Brand, Finding] | None:
    """paypa1.com, rnicrosoft.com, paypal-security.com (rules in app.lookalike)."""
    imitation = find_imitation(sender.org_domain)
    if imitation is None:
        return None
    brand, domain = imitation.brand, clip(sender.org_domain, 80)
    if imitation.kind == Kind.LOOKALIKE:
        return brand, finding(
            "sender.lookalike_domain", CATEGORY, Severity.HIGH,
            f"Sender domain imitates {brand.name}",
            f"{domain} looks almost identical to {brand.name}'s name "
            f"({imitation.target}), but it is a different domain.",
        )
    return brand, finding(
        "sender.brand_in_domain", CATEGORY, Severity.MEDIUM,
        f"Sender domain uses the {brand.name} name but is not owned by it",
        f"{domain} contains '{imitation.target}', but {brand.name} sends "
        f"from {', '.join(sorted(brand.domains))}.",
    )


def _merged_impersonation(sender: Address, brand: Brand, domain_finding: Finding) -> Finding:
    """One finding, scored for what the combination is.

    Name + near-identical domain (PayPal <x@paypa1.com>) is a deliberate
    disguise with no innocent explanation: critical. Name + brand word in a
    domain (paypal-help-center.com) is strong but a notch less certain: high.
    The domain finding's id is kept because patterns rely on it.
    """
    severity = Severity.CRITICAL if domain_finding.id == "sender.lookalike_domain" else Severity.HIGH
    return finding(
        domain_finding.id, CATEGORY, severity,
        f"Impersonates {brand.name}: both the name and the domain imitate it",
        f'Shown as "{clip(sender.display_name, 80)}" and sent from '
        f"{clip(sender.domain, 80)}, which is not {brand.name}'s. "
        f"{brand.name} sends from {', '.join(sorted(brand.domains))}.",
    )


def _punycode_domain(sender: Address) -> list[Finding]:
    """xn--pypal-4ve.com: international characters that look like Latin ones."""
    if any(part.startswith("xn--") for part in sender.domain.split(".")):
        return [finding(
            "sender.punycode_domain", CATEGORY, Severity.MEDIUM,
            "Sender domain uses look-alike international characters",
            f"{clip(sender.domain, 80)} is an encoded international domain, a common "
            "trick to imitate a familiar name (e.g. a Cyrillic 'а' instead of 'a').",
        )]
    return []


def _reply_to_mismatch(sender: Address, reply_to_header: str) -> list[Finding]:
    """Replies silently go somewhere other than the visible sender."""
    if not reply_to_header:
        return []
    reply_to = parse_address(reply_to_header)
    if reply_to is None or reply_to.org_domain == sender.org_domain:
        return []
    return [finding(
        "sender.reply_to_mismatch", CATEGORY, Severity.MEDIUM,
        "Replies go to a different address than the sender",
        f"Sent from {clip(sender.email, 80)}, but hitting Reply goes to "
        f"{clip(reply_to.email, 80)}.",
    )]
