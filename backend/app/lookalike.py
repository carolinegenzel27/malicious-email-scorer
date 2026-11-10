"""Detects domains that imitate a known brand: paypa1.com, paypal-security.com.

Shared by the sender and link analyzers so both use the same, tuned rules.
Tuning was driven by false positives on real domains: brands own ordinary
words (live.com, meta.com, apple.com), so only distinctive names are compared
and short names require a deliberate character swap (app1e), not any
one-letter difference (apply).
"""

from dataclasses import dataclass
from enum import Enum

from app.brands import BRANDS, Brand, is_free_email

# Characters attackers swap for look-alikes: paypa1.com, rnicrosoft.com.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "5": "s", "7": "t"})

# Edit distance ("one letter off") is only safe for long, distinctive names.
_MIN_LEN_FOR_EDIT_DISTANCE = 7
# Brand name inside a longer word (paypalsupport.com) only for long names;
# short ones must be a separate token (apple-id.com, not pineapple.com).
_MIN_LEN_FOR_AFFIX_MATCH = 6


class Kind(str, Enum):
    LOOKALIKE = "lookalike"  # near-identical spelling: stronger
    BRAND_IN_DOMAIN = "brand_in_domain"  # brand word embedded in another domain


@dataclass(frozen=True)
class Imitation:
    brand: Brand
    kind: Kind
    target: str  # the brand name that was imitated, e.g. "paypal"


def is_brand_owned(org_domain: str) -> bool:
    return any(org_domain in brand.domains for brand in BRANDS)


def find_imitation(org_domain: str) -> Imitation | None:
    """Return how org_domain imitates a brand, or None. Strongest match wins."""
    if is_free_email(org_domain) or is_brand_owned(org_domain):
        return None  # a provider or the brand itself

    label = org_domain.split(".")[0]
    tokens = [t for t in label.split("-") if t]

    for brand in BRANDS:  # pass 1: near-identical spelling
        for target in brand.lookalike_targets:
            if any(looks_like(part, target) for part in {label, *tokens}):
                return Imitation(brand, Kind.LOOKALIKE, target)
    for brand in BRANDS:  # pass 2: brand name embedded in another domain
        for target in brand.lookalike_targets:
            if _contains_brand(label, tokens, target):
                return Imitation(brand, Kind.BRAND_IN_DOMAIN, target)
    return None


def looks_like(candidate: str, target: str) -> bool:
    """True if candidate is a deliberate near-copy of target (but not identical)."""
    if candidate == target or len(target) < 4:
        return False
    if _skeleton(candidate) == _skeleton(target):
        return True  # paypa1, rnicrosoft, app1e
    if _is_doubled_letter_typo(candidate, target):
        return True  # paypall, gooogle
    if len(target) >= _MIN_LEN_FOR_EDIT_DISTANCE:
        max_edits = 1 if len(target) <= 8 else 2
        return edit_distance(candidate, target) <= max_edits  # netflx, mircosoft
    return False


def _contains_brand(label: str, tokens: list[str], target: str) -> bool:
    if target in tokens:
        return True  # paypal-security.com, apple-id.com, paypal.xyz
    if len(target) >= _MIN_LEN_FOR_AFFIX_MATCH:
        return label.startswith(target) or label.endswith(target)  # paypalsupport, mypaypal
    return False


def _skeleton(text: str) -> str:
    return text.replace("rn", "m").replace("vv", "w").translate(_HOMOGLYPHS)


def _is_doubled_letter_typo(candidate: str, target: str) -> bool:
    return any(
        candidate[i] == candidate[i - 1] and candidate[:i] + candidate[i + 1:] == target
        for i in range(1, len(candidate))
    )


def edit_distance(a: str, b: str) -> int:
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
