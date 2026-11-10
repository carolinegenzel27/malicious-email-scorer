"""Domain age: phishing campaigns use freshly registered domains.

Attackers register a new domain per campaign because old ones get blocked
quickly. Real organizations send from domains they have owned for years.
A new domain is a signal, not proof: new startups exist too.
"""

from datetime import datetime, timezone

from app import rdap
from app.analyzers.base import finding
from app.emailparse import parse_address
from app.models import EmailAnalysisRequest, Finding, Severity

CATEGORY = "sender"
NEW_DOMAIN_DAYS = 30
YOUNG_DOMAIN_DAYS = 180


def analyze_domain_age(email: EmailAnalysisRequest) -> list[Finding]:
    sender = parse_address(email.sender)
    if sender is None:
        return []  # the sender analyzer already reports a malformed address

    domain = sender.org_domain
    registered = rdap.registration_date(domain)
    if registered is None:
        return [
            finding(
                "sender.domain_age_unknown",
                CATEGORY,
                Severity.INFO,
                "Sender domain age unknown",
                f"Could not look up when {domain} was registered "
                "(some country domains, such as .co.il, do not publish it).",
            )
        ]

    age_days = days_since(registered)
    if age_days < NEW_DOMAIN_DAYS:
        return [
            finding(
                "sender.new_domain",
                CATEGORY,
                Severity.HIGH,
                "Sender domain was registered very recently",
                f"{domain} was registered {_ago(age_days)}. Phishing campaigns "
                "typically use brand-new domains.",
            )
        ]
    if age_days < YOUNG_DOMAIN_DAYS:
        return [
            finding(
                "sender.young_domain",
                CATEGORY,
                Severity.LOW,
                "Sender domain is only a few months old",
                f"{domain} was registered {_ago(age_days)}.",
            )
        ]
    return [
        finding(
            "sender.established_domain",
            CATEGORY,
            Severity.INFO,
            "Sender domain is well established",
            f"{domain} has existed since {registered.year}.",
        )
    ]


def days_since(moment: datetime, now: datetime | None = None) -> int:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return max(0, (now - moment).days)


def _ago(days: int) -> str:
    if days == 0:
        return "today"
    return f"{days} day{'s' if days != 1 else ''} ago"
