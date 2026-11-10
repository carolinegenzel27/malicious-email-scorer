"""Helpers for parsing untrusted email header values."""

from dataclasses import dataclass
from email.utils import parseaddr

# Public suffixes made of two labels, where the "organization" is the third
# label from the right (paypal.co.uk -> paypal.co.uk, not co.uk).
# A full Public Suffix List would be more accurate; this covers common cases
# without a runtime download. Documented as a known limitation.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il",
    "com.au", "net.au", "org.au",
    "co.jp", "co.in", "co.nz", "co.za", "com.br", "com.mx", "com.tr",
}


@dataclass(frozen=True)
class Address:
    display_name: str
    email: str  # lower-cased
    domain: str  # lower-cased full domain, e.g. "mail.paypal.com"

    @property
    def org_domain(self) -> str:
        """Registrable domain, e.g. mail.paypal.com -> paypal.com."""
        return org_domain(self.domain)


def parse_address(header_value: str) -> Address | None:
    """Parse a From / Reply-To style header. Returns None if no valid address."""
    name, email = parseaddr(header_value or "")
    email = email.strip().lower()
    if "@" not in email:
        return None
    domain = email.rsplit("@", 1)[1].strip(".")
    if not domain:
        return None
    return Address(display_name=name.strip(), email=email, domain=domain)


def org_domain(domain: str) -> str:
    labels = domain.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def clip(text: str, limit: int = 200) -> str:
    """Shorten attacker-controlled evidence before echoing it back."""
    return text if len(text) <= limit else text[: limit - 1] + "…"
