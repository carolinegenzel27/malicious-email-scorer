"""Extracts links from untrusted email bodies.

The HTML is only PARSED, never rendered or executed, and links are never
fetched: visiting an attacker's URL could confirm the mailbox is live,
pull malware onto the server, or be abused to reach internal addresses (SSRF).
"""

import ipaddress
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_LINKS = 100  # enough for any real email; bounds work on crafted input
MAX_TEXT_LEN = 300

_URL_IN_TEXT_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


@dataclass(frozen=True)
class Link:
    url: str
    host: str  # lower-cased hostname, no port
    text: str = ""  # visible link text ("" for bare URLs in plain text)

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host.strip("[]"))
            return True
        except ValueError:
            return False


def extract_links(body_html: str, body_text: str) -> list[Link]:
    """All http(s) links, de-duplicated, capped at MAX_LINKS."""
    found: dict[tuple[str, str], Link] = {}
    candidates = _AnchorParser.parse(body_html) + [(url, "") for url in _URL_IN_TEXT_RE.findall(body_text)]
    for url, text in candidates:
        link = _make_link(url, text)
        if link and (link.url, link.text) not in found:
            found[(link.url, link.text)] = link
            if len(found) >= MAX_LINKS:
                break
    return list(found.values())


def _make_link(url: str, text: str) -> Link | None:
    url = url.strip()
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:  # malformed, e.g. broken IPv6 brackets
        return None
    if parts.scheme.lower() not in {"http", "https"} or not host:
        return None  # mailto:, tel:, anchors, relative links
    return Link(url=url, host=host, text=" ".join(text.split())[:MAX_TEXT_LEN])


class _AnchorParser(HTMLParser):
    """Collects (href, visible text) for every <a> tag."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    @classmethod
    def parse(cls, html: str) -> list[tuple[str, str]]:
        parser = cls()
        try:
            parser.feed(html)
            parser.close()
        except Exception:  # noqa: BLE001 - malformed HTML must never break analysis
            pass
        parser._finish()  # an <a> left unclosed at the end still counts
        return parser.anchors[:MAX_LINKS]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._finish()
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._finish()

    def _finish(self) -> None:
        if self._href:
            self.anchors.append((self._href, "".join(self._text)))
        self._href = None
        self._text = []
