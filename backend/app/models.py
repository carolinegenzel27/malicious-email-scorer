"""API contract between the Gmail add-on and the backend.

Everything in `EmailAnalysisRequest` is attacker-controlled (it comes from an
email), so every field has an explicit size bound. Pydantic rejects oversized
or malformed input with HTTP 422 before any analysis code runs.

Data minimization: the request holds only fields an analyzer actually uses.
Unknown fields are rejected, so nothing extra can be sent by mistake.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

# Size limits. Generous enough for real email, small enough to stop abuse.
MAX_HEADER_LEN = 4_000
MAX_SUBJECT_LEN = 1_000
MAX_BODY_LEN = 200_000
MAX_ATTACHMENTS = 30


class _StrictModel(BaseModel):
    # Reject unknown fields instead of silently ignoring them.
    model_config = ConfigDict(extra="forbid")


# ---------- Request ----------


class Attachment(_StrictModel):
    """Only the file's NAME and declared TYPE. Contents, sizes and hashes never
    leave Gmail: the name alone reveals the tricks this checks for."""

    filename: str = Field(max_length=255)
    content_type: str = Field(default="", max_length=100)


class EmailAnalysisRequest(_StrictModel):
    sender: str = Field(max_length=MAX_HEADER_LEN, description="Raw From header")
    reply_to: str = Field(default="", max_length=MAX_HEADER_LEN)
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
    category: str = Field(
        description="authentication | sender | links | content | attachments | attack pattern"
    )
    severity: Severity
    title: str = Field(description="Short, plain-language headline for the user")
    detail: str = Field(description="Evidence: what exactly we saw")
    points: int = Field(
        ge=-100,
        le=100,
        description="Contribution to the 0-100 score (negative = reassuring evidence)",
    )


class AnalysisResult(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    summary: str
    findings: list[Finding]
