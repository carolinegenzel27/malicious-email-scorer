"""Attack pattern recognition: combinations of findings that match a known attack.

A single signal often has an innocent explanation (new startups have new
domains). Certain COMBINATIONS do not: a brand name on a three-day-old domain
is phishing. Patterns turn a list of technical findings into one named,
understandable verdict.

Rules to keep the score honest:
- Only the strongest matching attack pattern adds bonus points; others are
  listed with 0 points so they explain without inflating the score.
- Reassuring patterns only apply when no attack pattern matched.
"""

from dataclasses import dataclass

from app.analyzers.base import finding
from app.models import Finding, Severity

ATTACK_BONUS = 25
REASSURING_DEDUCTION = -10


@dataclass(frozen=True)
class Pattern:
    id: str
    name: str
    # Every group must be satisfied; a group is satisfied by ANY of its finding ids.
    requires: tuple[frozenset[str], ...]
    explanation: str
    reassuring: bool = False


def _any(*ids: str) -> frozenset[str]:
    return frozenset(ids)


IMPERSONATION = _any(
    "sender.brand_impersonation", "sender.lookalike_domain",
    "sender.brand_in_domain", "sender.punycode_domain",
)
LOOKALIKE_DOMAIN = _any("sender.lookalike_domain", "sender.brand_in_domain", "sender.punycode_domain")
SUSPICIOUS_LINK = _any(
    "links.text_mismatch", "links.lookalike_domain", "links.brand_in_domain",
    "links.ip_address", "links.punycode_domain", "links.shortener",
)
# The reply would not reach who the user thinks wrote it.
DIVERTED_IDENTITY = _any(
    "sender.reply_to_mismatch", "sender.free_email",
    "sender.brand_impersonation", "sender.name_contains_other_address",
)
# Either way, the sender's own domain vouched for the message.
AUTHENTICATED = _any("auth.dmarc_pass", "auth.spf_dkim_pass")

PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        id="pattern.brand_spoofing_new_domain",
        name="Brand impersonation from a brand-new domain",
        requires=(IMPERSONATION, _any("sender.new_domain")),
        explanation="The email poses as a well-known brand, but its domain was registered "
                    "only days ago. Real brands do not send from brand-new domains.",
    ),
    Pattern(
        id="pattern.credential_phishing",
        name="Credential phishing",
        requires=(_any("content.credential_request"), SUSPICIOUS_LINK),
        explanation="The email asks you to verify your account or enter login details, and "
                    "its link leads to a disguised site. This is how passwords are stolen.",
    ),
    Pattern(
        id="pattern.ceo_fraud",
        name="CEO / payment fraud",
        requires=(
            _any("content.money_request"),
            _any("content.urgency", "content.secrecy"),
            DIVERTED_IDENTITY,
        ),
        explanation="A money request with pressure or secrecy, from an identity that does not "
                    "hold up (replies go elsewhere, or a free or impersonated address). Verify "
                    "by phone before paying anything.",
    ),
    Pattern(
        id="pattern.attacker_owned_lookalike",
        name="Look-alike domain owned by the attacker",
        requires=(LOOKALIKE_DOMAIN, AUTHENTICATED),
        explanation="Authentication passed only because the sender owns this look-alike "
                    "domain. Passing checks here means the forgery is well prepared, not safe.",
    ),
    Pattern(
        id="pattern.verified_brand",
        name="Verified sender",
        requires=(_any("sender.brand_domain_match"), _any("auth.dmarc_pass")),
        explanation="The brand in the sender name matches its real domain, and Gmail "
                    "verified the message really comes from that domain.",
        reassuring=True,
    ),
)


def detect_patterns(findings: list[Finding]) -> list[Finding]:
    """Return pattern findings to add to the analysis."""
    present = {f.id for f in findings}
    matched = [p for p in PATTERNS if all(group & present for group in p.requires)]

    attacks = [p for p in matched if not p.reassuring]
    if attacks:
        # PATTERNS is ordered strongest-first: the first match gets the bonus.
        return [_attack_finding(p, ATTACK_BONUS if i == 0 else 0) for i, p in enumerate(attacks)]
    return [_reassuring_finding(p) for p in matched if p.reassuring]


def _attack_finding(pattern: Pattern, points: int) -> Finding:
    return finding(
        pattern.id, "attack pattern", Severity.HIGH,
        f"Attack pattern: {pattern.name}", pattern.explanation, points=points,
    )


def _reassuring_finding(pattern: Pattern) -> Finding:
    return finding(
        pattern.id, "attack pattern", Severity.INFO,
        pattern.name, pattern.explanation, points=REASSURING_DEDUCTION,
    )
