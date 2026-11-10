"""Sender identity: is the sender who they appear to be?

Users judge an email mostly by the display name ("PayPal"), not the address
behind it. These checks compare what the user SEES with what is REAL.
"""

import re

from app.analyzers.base import finding
from app.brands import BRANDS, Brand
from app.emailparse import Address, clip, parse_address
from app.models import EmailAnalysisRequest, Finding, Severity

CATEGORY = "sender"

_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

# Characters attackers swap for look-alikes: paypa1.com, rnicrosoft.com.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "5": "s", "7": "t"})


def analyze_sender(email: EmailAnalysisRequest) -> list[Finding]:
    sender = parse_address(email.sender)
    if sender is None:
        return [
            finding(
                "sender.invalid",
                CATEGORY,
                Severity.MEDIUM,
                "Sender address is missing or malformed",
                f"Could not read a valid email address from: {clip(email.sender, 100)!r}",
            )
        ]

    findings: list[Finding] = []
    findings += _display_name_brand(sender)
    findings += _display_name_has_other_address(sender)
    findings += _lookalike_domain(sender)
    findings += _reply_to_mismatch(sender, email.reply_to)
    return findings


# ---------- individual checks ----------


def _display_name_brand(sender: Address) -> list[Finding]:
    """'PayPal Support' <alerts@random-site.com>"""
    name = sender.display_name.lower()
    for brand in BRANDS:
        if _mentions(name, brand) and sender.org_domain not in brand.domains:
            return [
                finding(
                    "sender.brand_impersonation",
                    CATEGORY,
                    Severity.HIGH,
                    f"Display name claims to be {brand.name}, but the address is not",
                    f'Shown as "{clip(sender.display_name, 80)}", but sent from '
                    f"{clip(sender.domain, 80)}. {brand.name} sends from "
                    f"{', '.join(sorted(brand.domains))}.",
                )
            ]
    return []


def _display_name_has_other_address(sender: Address) -> list[Finding]:
    """'security@paypal.com' <attacker@evil.com> - the name looks like an address."""
    match = _EMAIL_IN_TEXT_RE.search(sender.display_name)
    if match and match.group(0).lower() != sender.email:
        return [
            finding(
                "sender.name_contains_other_address",
                CATEGORY,
                Severity.HIGH,
                "Display name shows a different email address",
                f"The name shows {clip(match.group(0), 80)}, but the real sender is "
                f"{clip(sender.email, 80)}.",
            )
        ]
    return []


def _lookalike_domain(sender: Address) -> list[Finding]:
    """paypa1.com, rnicrosoft.com, paypal-security.com, xn--pypal-4ve.com"""
    findings: list[Finding] = []
    domain = sender.org_domain
    label = domain.split(".")[0]

    if any(part.startswith("xn--") for part in sender.domain.split(".")):
        findings.append(finding(
            "sender.punycode_domain",
            CATEGORY,
            Severity.MEDIUM,
            "Sender domain uses look-alike international characters",
            f"{clip(sender.domain, 80)} is an encoded international domain, a common "
            "trick to imitate a familiar name (e.g. a Cyrillic 'а' instead of 'a').",
        ))

    for brand in BRANDS:
        if domain in brand.domains:
            return findings  # this IS the real brand
        for real in brand.domains:
            real_label = real.split(".")[0]
            if len(real_label) < 4:
                continue  # too short to compare without false positives
            if _looks_like(label, real_label):
                findings.append(finding(
                    "sender.lookalike_domain",
                    CATEGORY,
                    Severity.HIGH,
                    f"Sender domain imitates {brand.name}",
                    f"{clip(domain, 80)} looks almost identical to {real}, but it is a "
                    "different domain.",
                ))
                return findings
            if real_label in label:
                findings.append(finding(
                    "sender.brand_in_domain",
                    CATEGORY,
                    Severity.MEDIUM,
                    f"Sender domain uses the {brand.name} name but is not owned by it",
                    f"{clip(domain, 80)} contains '{real_label}', but {brand.name} "
                    f"sends from {', '.join(sorted(brand.domains))}.",
                ))
                return findings
    return findings


def _reply_to_mismatch(sender: Address, reply_to_header: str) -> list[Finding]:
    """Replies silently go somewhere other than the visible sender."""
    if not reply_to_header:
        return []
    reply_to = parse_address(reply_to_header)
    if reply_to is None or reply_to.org_domain == sender.org_domain:
        return []
    return [
        finding(
            "sender.reply_to_mismatch",
            CATEGORY,
            Severity.MEDIUM,
            "Replies go to a different address than the sender",
            f"Sent from {clip(sender.email, 80)}, but hitting Reply goes to "
            f"{clip(reply_to.email, 80)}.",
        )
    ]


# ---------- helpers ----------


def _mentions(text: str, brand: Brand) -> bool:
    return any(
        re.search(rf"(?<![\w]){re.escape(keyword)}(?![\w])", text) for keyword in brand.keywords
    )


def _looks_like(candidate: str, real: str) -> bool:
    """True if candidate is a near-copy of real (but not identical)."""
    if candidate == real:
        return False
    if _skeleton(candidate) == _skeleton(real):
        return True
    max_edits = 1 if len(real) < 6 else 2
    return _edit_distance(candidate, real) <= max_edits


def _skeleton(text: str) -> str:
    return text.replace("rn", "m").replace("vv", "w").translate(_HOMOGLYPHS)


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance: how many single-character edits turn a into b."""
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,  # deletion
                current[j - 1] + 1,  # insertion
                previous[j - 1] + (char_a != char_b),  # substitution
            ))
        previous = current
    return previous[-1]
