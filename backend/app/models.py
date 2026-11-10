"""API contract between the Gmail add-on and the backend.

Everything in `EmailAnalysisRequest` is attacker-controlled (it comes from an
email), so every field has an explicit size bound. Pydantic rejects oversized
or malformed input with HTTP 422 before any analysis code runs.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

# Size limits. Generous enough for real email, small enough to stop abuse.
MAX_HEADER_LEN = 4_000
MAX_SUBJECT_LEN = 1_000
MAX_BODY_LEN = 200_000
MAX_ATTACHMENTS = 50


class _StrictModel(BaseModel):
    # Reject unknown fields instead of silently ignoring them.
    model_config = ConfigDict(extra="forbid")


# ---------- Request ----------


class Attachment(_StrictModel):
    """Attachment METADATA only. File contents are never sent to the backend."""

    filename: str = Field(max_length=500)
    content_type: str = Field(default="", max_length=200)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(default="", pattern=r"^([a-f0-9]{64})?$")


class EmailAnalysisRequest(_StrictModel):
    sender: str = Field(max_length=MAX_HEADER_LEN, description="Raw From header")
    reply_to: str = Field(default="", max_length=MAX_HEADER_LEN)
    return_path: str = Field(default="", max_length=MAX_HEADER_LEN)
    subject: str = Field(default="", max_length=MAX_SUBJECT_LEN)
    authentication_results: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="Values of Authentication-Results headers added by Gmail",
    )
    body_text: str = Field(default="", max_length=MAX_BODY_LEN)
    body_html: str = Field(default="", max_length=MAX_BODY_LEN)
    attachments: list[Attachment] = Field(default_factory=list, max_length=MAX_ATTACHMENTS)


# ---------- Response ----------


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Severity(str, Enum):
    INFO = "info"  # context, does not raise the score (e.g. "DKIM passed")
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"  # forces a malicious verdict on its own


class Finding(BaseModel):
    """One explainable reason that contributed to the score."""

    id: str = Field(description="Stable machine id, e.g. 'auth.dmarc_fail'")
    category: str = Field(description="authentication | sender | links | content | attachments")
    severity: Severity
    title: str = Field(description="Short, plain-language headline for the user")
    detail: str = Field(description="Evidence: what exactly we saw")
    points: int = Field(ge=0, description="Contribution to the 0-100 score")


class AnalysisResult(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    summary: str
    findings: list[Finding]
