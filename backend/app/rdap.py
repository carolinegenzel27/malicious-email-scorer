"""Domain registration date lookup via RDAP (the modern, JSON-based WHOIS).

The domain comes from an email, so it is untrusted:
- It is validated against a strict pattern before being put in a URL, so a
  crafted value like "evil.com/../admin?x=" cannot change the request.
- Only the domain name is sent to RDAP - never any email content.
- The RDAP response is external input: size-limited and parsed defensively.
- A short timeout keeps us inside Gmail's ~30s add-on limit.
"""

import logging
import re
from datetime import datetime
from functools import lru_cache

import httpx

logger = logging.getLogger(__name__)

RDAP_URL = "https://rdap.org/domain/{domain}"  # redirects to the right registry
TIMEOUT_SECONDS = 3.0
MAX_RESPONSE_BYTES = 512_000

# Letters, digits and hyphens per label (incl. punycode "xn--"), 2+ labels.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def is_valid_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain))


@lru_cache(maxsize=2048)
def registration_date(domain: str) -> datetime | None:
    """Return when the domain was registered, or None if unknown.

    Cached: a domain's registration date does not change, and the same
    senders appear again and again. Failures are cached too, so one slow
    registry is not hit repeatedly.
    """
    domain = domain.lower()
    if not is_valid_domain(domain):
        return None
    try:
        with httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=True, max_redirects=3) as client:
            response = client.get(RDAP_URL.format(domain=domain))
        if response.status_code != 200 or len(response.content) > MAX_RESPONSE_BYTES:
            return None
        return parse_registration_date(response.json())
    except (httpx.HTTPError, ValueError):
        # Unknown age is not suspicious in itself (many ccTLDs, e.g. .co.il,
        # do not offer RDAP). Log the domain only.
        logger.info("RDAP lookup failed for %s", domain)
        return None


def parse_registration_date(data: object) -> datetime | None:
    if not isinstance(data, dict):
        return None
    events = data.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            try:
                return datetime.fromisoformat(str(event.get("eventDate", "")))
            except ValueError:
                return None
    return None
