"""Attachments: is a file disguised or dangerous to open?

Works from the file NAME and declared type only - contents never leave Gmail.
The name alone reveals the classic delivery tricks:

- files that run code when opened (.exe, .js, .lnk, .iso ...)
- macro-enabled Office documents (.docm, .xlsm)
- HTML files, which open a local fake login page that no link filter sees
- a decoy extension in front of the real one (invoice.pdf.exe)
- a right-to-left override character that makes "invoice‮fdp.exe"
  display as "invoiceexe.pdf"

One finding per type with examples, and a disguised file is reported once
(as disguised), not again as dangerous.
"""

from app.analyzers.base import finding
from app.emailparse import clip
from app.models import EmailAnalysisRequest, Finding, Severity

CATEGORY = "attachments"
MAX_EXAMPLES = 3

# Run code when opened, or mount/launch something that does.
EXECUTABLE = frozenset({
    "exe", "scr", "com", "bat", "cmd", "pif", "msi", "cpl", "lnk", "hta", "jar",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "reg", "iso", "img", "vhd",
})
MACRO_OFFICE = frozenset({"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppsm"})
HTML = frozenset({"html", "htm", "shtml", "xhtml", "svg"})
RISKY = EXECUTABLE | MACRO_OFFICE | HTML

# Extensions people trust, used as the decoy in front of the real one.
DECOY = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rtf",
    "jpg", "jpeg", "png", "gif", "zip", "mp3", "mp4", "wav",
})

# Bidirectional override characters that reverse how the name is displayed.
BIDI_OVERRIDES = frozenset({"‮", "‭"})


def analyze_attachments(email: EmailAnalysisRequest) -> list[Finding]:
    disguised: list[str] = []
    reversed_names: list[str] = []
    executable: list[str] = []
    macro: list[str] = []
    html: list[str] = []

    for attachment in email.attachments:
        raw = attachment.filename
        shown = clip(_visible(raw), 80)
        if any(ch in raw for ch in BIDI_OVERRIDES):
            reversed_names.append(shown)
            continue
        extensions = _extensions(raw)
        if not extensions:
            continue
        real = extensions[-1]
        if real in RISKY and len(extensions) >= 2 and extensions[-2] in DECOY:
            disguised.append(shown)
        elif real in EXECUTABLE:
            executable.append(shown)
        elif real in MACRO_OFFICE:
            macro.append(shown)
        elif real in HTML:
            html.append(shown)

    findings: list[Finding] = []
    if reversed_names:
        findings.append(finding(
            "attachments.reversed_name", CATEGORY, Severity.CRITICAL,
            "File name is reversed to hide its real type",
            f"{_examples(reversed_names)} contains a hidden character that flips how the "
            "name is displayed, so a program can look like a document.",
        ))
    if disguised:
        findings.append(finding(
            "attachments.double_extension", CATEGORY, Severity.CRITICAL,
            "File is disguised with a fake extension",
            f"{_examples(disguised)} looks like a harmless document, but the real type "
            "is the last extension.",
        ))
    if executable:
        findings.append(finding(
            "attachments.executable", CATEGORY, Severity.HIGH,
            "Attachment runs code when opened",
            f"{_examples(executable)} is a program or script, rarely sent by email legitimately.",
        ))
    if macro:
        findings.append(finding(
            "attachments.macro_document", CATEGORY, Severity.MEDIUM,
            "Office document with macros",
            f"{_examples(macro)} can run macros, a common way to install malware.",
        ))
    if html:
        findings.append(finding(
            "attachments.html", CATEGORY, Severity.MEDIUM,
            "HTML file attached",
            f"{_examples(html)} opens a web page from your computer, a common way to show a "
            "fake login page that link filters never see.",
        ))
    return findings


def _extensions(filename: str) -> list[str]:
    # Windows ignores trailing dots and spaces: "invoice.exe. " runs as .exe.
    name = filename.strip().rstrip(". ").lower()
    parts = name.split(".")
    return [p.strip() for p in parts[1:] if p.strip()]


def _visible(filename: str) -> str:
    """Drop invisible bidi controls so the evidence shows the real characters."""
    return "".join(ch for ch in filename if ch not in BIDI_OVERRIDES and ch not in "⁦⁧⁨⁩")


def _examples(names: list[str]) -> str:
    unique = list(dict.fromkeys(names))
    shown = ", ".join(unique[:MAX_EXAMPLES])
    extra = len(unique) - MAX_EXAMPLES
    return shown + (f" (and {extra} more)" if extra > 0 else "")
