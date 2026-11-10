"""Sender authentication: SPF, DKIM and DMARC.

Gmail records these checks in an Authentication-Results header:

    mx.google.com; dkim=pass header.i=@paypal.com; spf=pass ...;
    dmarc=pass (p=REJECT) header.from=paypal.com

Security note: anyone can put a fake Authentication-Results header in the
email they send. We only trust results stamped by Gmail's own server
("authserv-id" mx.google.com), which Gmail adds on receipt.
"""

import re
from dataclasses import dataclass

from app.analyzers.base import finding
from app.emailparse import clip
from app.models import EmailAnalysisRequest, Finding, Severity

TRUSTED_AUTHSERV_IDS = {"mx.google.com"}
CATEGORY = "authentication"

_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_HEADER_FROM_RE = re.compile(r"header\.from\s*=\s*([^\s;]+)", re.IGNORECASE)


@dataclass
class AuthResults:
    spf: str = "missing"
    dkim: str = "missing"
    dmarc: str = "missing"
    header_from: str = ""


def parse_authentication_results(headers: list[str]) -> AuthResults | None:
    """Return results from the first trusted header, or None if none is trusted."""
    for header in headers:
        authserv_id = header.split(";", 1)[0].strip().lower()
        if authserv_id not in TRUSTED_AUTHSERV_IDS:
            continue
        results = AuthResults()
        for method, value in _RESULT_RE.findall(header):
            method, value = method.lower(), value.lower()
            # A message can carry several DKIM signatures: one pass is enough.
            if method == "dkim" and results.dkim == "pass":
                continue
            setattr(results, method, value)
        if match := _HEADER_FROM_RE.search(header):
            results.header_from = match.group(1).lower()
        return results
    return None


def analyze_authentication(email: EmailAnalysisRequest) -> list[Finding]:
    results = parse_authentication_results(email.authentication_results)
    if results is None:
        return [
            finding(
                "auth.no_trusted_results",
                CATEGORY,
                Severity.LOW,
                "Sender could not be verified",
                "No authentication results from Gmail were found, so SPF, DKIM "
                "and DMARC could not be checked.",
            )
        ]

    domain = clip(results.header_from or "the sender's domain", 100)

    # DMARC is the summary verdict: it passes only if SPF or DKIM passed AND
    # matches the visible From domain. If it passed, individual SPF/DKIM
    # failures are usually harmless (e.g. forwarding breaks SPF).
    if results.dmarc == "pass":
        return [
            finding(
                "auth.dmarc_pass",
                CATEGORY,
                Severity.INFO,
                "Sender domain verified (DMARC pass)",
                f"The message really comes from {domain}. This proves who sent "
                "it, not that the sender is trustworthy.",
            )
        ]
    if results.dmarc == "fail":
        return [
            finding(
                "auth.dmarc_fail",
                CATEGORY,
                Severity.HIGH,
                "Sender domain failed verification (DMARC fail)",
                f"The message claims to be from {domain} but failed DMARC, "
                "a strong sign that the sender address is forged.",
            )
        ]

    # No DMARC verdict: fall back to the individual checks.
    findings: list[Finding] = []
    if results.spf == "fail":
        findings.append(finding(
            "auth.spf_fail", CATEGORY, Severity.MEDIUM,
            "Sent from a server not authorized by the domain (SPF fail)",
            f"{domain} does not list the sending server as allowed to send its email.",
        ))
    elif results.spf in {"softfail", "none", "neutral", "permerror", "temperror", "missing"}:
        findings.append(finding(
            "auth.spf_weak", CATEGORY, Severity.LOW,
            f"Sending server not confirmed (SPF {results.spf})",
            "The sender's domain does not clearly authorize the server that sent this email.",
        ))

    if results.dkim == "fail":
        findings.append(finding(
            "auth.dkim_fail", CATEGORY, Severity.MEDIUM,
            "Digital signature is invalid (DKIM fail)",
            "The message's signature does not verify: it may have been altered or forged.",
        ))
    elif results.dkim != "pass":
        findings.append(finding(
            "auth.dkim_missing", CATEGORY, Severity.LOW,
            "Message is not digitally signed (no DKIM)",
            "Without a signature, the sender's identity cannot be confirmed.",
        ))

    if not findings:
        findings.append(finding(
            "auth.spf_dkim_pass", CATEGORY, Severity.INFO,
            "SPF and DKIM passed",
            "The sending server and the message signature were verified.",
        ))
    return findings
