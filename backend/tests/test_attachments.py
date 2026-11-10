import pytest

from app.analysis import analyze
from app.analyzers.attachments import analyze_attachments
from app.models import Attachment, EmailAnalysisRequest, Severity, Verdict


def run(*names: str, sender: str = "Colleague <dana@example.com>"):
    email = EmailAnalysisRequest(sender=sender, attachments=[Attachment(filename=n) for n in names])
    return analyze_attachments(email)


def ids(*names: str) -> set[str]:
    return {f.id for f in run(*names)}


# ---------- everyday attachments stay clean ----------


@pytest.mark.parametrize(
    "name",
    [
        "report.pdf", "Q3 results.xlsx", "slides.pptx", "contract.docx", "photo.JPG", "scan.png",
        "invite.ics", "notes.txt", "archive.zip", "data.csv", "signature.gif", "README",
        "v1.2.3 release notes.pdf",  # dots inside the name are not extensions
        "חשבונית.pdf",
    ],
)
def test_everyday_attachments_are_clean(name):
    assert ids(name) == set()


# ---------- detections ----------


@pytest.mark.parametrize("name", ["setup.exe", "invoice.js", "shortcut.lnk", "parcel.iso", "run.PS1"])
def test_executable(name):
    assert ids(name) == {"attachments.executable"}


@pytest.mark.parametrize("name", ["invoice.docm", "budget.xlsm"])
def test_macro_document(name):
    assert ids(name) == {"attachments.macro_document"}


@pytest.mark.parametrize("name", ["login.html", "secure-message.htm", "logo.svg"])
def test_html_attachment(name):
    assert ids(name) == {"attachments.html"}


@pytest.mark.parametrize("name", ["invoice.pdf.exe", "scan.jpg.js", "statement.pdf.html", "order.docx.docm"])
def test_double_extension_is_critical(name):
    findings = run(name)
    assert [f.id for f in findings] == ["attachments.double_extension"]
    assert findings[0].severity == Severity.CRITICAL


def test_trailing_dots_and_spaces_do_not_hide_the_real_type():
    assert ids("invoice.pdf.exe. ") == {"attachments.double_extension"}
    assert ids("update.exe.") == {"attachments.executable"}


def test_right_to_left_override_trick():
    # Displays as "invoiceexe.pdf" but is really invoice<RLO>fdp.exe
    findings = run("invoice‮fdp.exe")
    assert [f.id for f in findings] == ["attachments.reversed_name"]
    assert "‮" not in findings[0].detail  # evidence shows the real characters


# ---------- no duplicates ----------


def test_one_finding_per_type():
    findings = run("a.exe", "b.exe", "c.exe", "d.exe", "e.exe")
    assert len(findings) == 1
    assert "(and 2 more)" in findings[0].detail


def test_disguised_file_is_not_counted_again_as_executable():
    assert ids("invoice.pdf.exe") == {"attachments.double_extension"}


# ---------- patterns, end to end ----------


def test_disguised_attachment_from_fake_courier_is_malware_delivery():
    result = analyze(EmailAnalysisRequest(
        sender="DHL Express <tracking@dhl-parcel-notice.com>",
        attachments=[Attachment(filename="Invoice_48213.pdf.html", content_type="text/html")],
    ))
    assert result.findings[0].id == "pattern.malware_delivery"
    assert result.verdict == Verdict.MALICIOUS


def test_colleagues_macro_spreadsheet_is_not_malware_delivery():
    result = analyze(EmailAnalysisRequest(
        sender="Finance <finance@acme-industries.com>",
        attachments=[Attachment(filename="budget.xlsm")],
        authentication_results=[
            "mx.google.com; dkim=pass; spf=pass; dmarc=pass header.from=acme-industries.com"
        ],
    ))
    assert "pattern.malware_delivery" not in {f.id for f in result.findings}
    assert result.verdict == Verdict.SAFE
