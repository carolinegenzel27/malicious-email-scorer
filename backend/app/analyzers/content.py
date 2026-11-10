"""Content: what is the email asking the user to do?

The other analyzers judge WHO sent the email and WHERE its links lead. This
one reads WHAT it asks for. Social-engineering emails, especially CEO fraud
with no links at all, give themselves away by their requests: pay, log in,
hurry, keep it secret.

Deliberately simple and transparent: curated phrases in English and Hebrew,
one finding per group. Phrases are specific ("wire transfer", not "payment";
"keep this confidential", not "confidential") because legitimate mail is full
of generic words - receipts mention payments, legal footers say confidential.
An ML/LLM classifier would catch more paraphrases, but is slower, harder to
explain, and an LLM reading attacker text is open to prompt injection.
"""

import re
from dataclasses import dataclass
from html.parser import HTMLParser

from app.analyzers.base import finding
from app.models import EmailAnalysisRequest, Finding, Severity

CATEGORY = "content"


@dataclass(frozen=True)
class PhraseGroup:
    id: str
    severity: Severity
    title: str
    phrases: tuple[str, ...]


GROUPS: tuple[PhraseGroup, ...] = (
    PhraseGroup(
        "content.money_request", Severity.MEDIUM, "Asks for a money transfer or payment",
        (
            "wire transfer", "bank transfer", "wire the funds", "wire the money", "send the payment",
            "gift card", "gift cards", "itunes card", "change of bank details", "new bank account",
            "updated bank details",
            "העברה בנקאית", "להעביר כסף", "כרטיס מתנה", "כרטיסי מתנה",
            "פרטי חשבון הבנק", "חשבון בנק חדש",
        ),
    ),
    PhraseGroup(
        "content.credential_request", Severity.MEDIUM, "Asks you to verify an account or enter login details",
        (
            "verify your account", "verify your identity", "confirm your identity", "confirm your details",
            "confirm your password", "enter your password", "update your billing", "update your payment",
            "unlock your account", "restore your account", "validate your account",
            "יש לאמת", "לאמת את פרטיך", "לאימות החשבון", "אימות החשבון", "הזן סיסמה", "הזיני סיסמה",
            "פרטי כרטיס האשראי", "לעדכן את פרטי התשלום",
        ),
    ),
    PhraseGroup(
        "content.urgency", Severity.LOW, "Pressures you to act immediately",
        (
            "urgent", "immediately", "within 24 hours", "within 48 hours", "final notice", "act now",
            "account has been limited", "account will be suspended", "avoid suspension",
            "account will be closed", "needed today",
            "דחוף", "באופן מיידי", "תוך 24 שעות", "תוך 48 שעות", "הודעה אחרונה", "החשבון יינעל",
            "החשבון ייחסם", "למנוע חסימה", "הוגבל",
        ),
    ),
    PhraseGroup(
        "content.secrecy", Severity.LOW, "Asks you to keep it secret",
        (
            "keep this confidential", "keep it confidential", "keep this between us", "don't tell anyone",
            "do not tell anyone", "do not discuss this", "don't mention this",
            "בסודיות", "שיישאר בינינו", "אל תספר", "אל תספרי", "לא לספר לאף אחד",
        ),
    ),
)

MAX_EXAMPLES = 3


def _compile(phrases: tuple[str, ...]) -> re.Pattern[str]:
    # Latin phrases must match whole words ("urgent" not in "insurgent").
    # Hebrew attaches prefixes to words (ו/ה/ב...), so Hebrew matches anywhere.
    parts = [
        re.escape(p) if not p.isascii() else rf"(?<![a-z]){re.escape(p)}(?![a-z])"
        for p in phrases
    ]
    return re.compile("|".join(parts))


_PATTERNS = {group.id: _compile(group.phrases) for group in GROUPS}


def analyze_content(email: EmailAnalysisRequest) -> list[Finding]:
    text = normalize(email.subject + "\n" + (email.body_text or html_to_text(email.body_html)))
    findings = []
    for group in GROUPS:
        matches = list(dict.fromkeys(m.group(0) for m in _PATTERNS[group.id].finditer(text)))
        if matches:
            quoted = ", ".join(f'"{m}"' for m in matches[:MAX_EXAMPLES])
            findings.append(finding(group.id, CATEGORY, group.severity, group.title, f"Found: {quoted}."))
    return findings


def normalize(text: str) -> str:
    # Lower-case, unify curly apostrophes, collapse whitespace and line breaks.
    return " ".join(text.lower().replace("’", "'").split())


def html_to_text(html: str) -> str:
    """Visible text of an HTML body (fallback when there is no plain-text part)."""
    parser = _TextParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed HTML must never break analysis
        pass
    return " ".join(parser.chunks)


class _TextParser(HTMLParser):
    _SKIP = {"script", "style", "head"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.chunks.append(data)
