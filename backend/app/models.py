from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["high", "medium", "low", "info"]
Lever = Literal["urgency", "fear", "authority", "greed", "curiosity", "none"]
Verdict = Literal["low", "suspicious", "high"]
LookupStatus = Literal["ok", "not_connected", "could_not_run", "skipped"]


class UrlPart(BaseModel):
    protocol: str = ""
    subdomain: str = ""
    domain: str = ""
    path: str = ""
    query: str = ""
    fragment: str = ""
    host: str = ""
    original: str
    registrable_domain: str = ""
    is_ip: bool = False
    uses_https: bool = False


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    score_points: int = 0
    explanation: str
    lever: Lever = "none"
    category: str
    evidence: str = ""


class ExternalCheck(BaseModel):
    name: str
    status: LookupStatus
    source: str
    checked_at: Optional[str] = None
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)


class AttachmentMeta(BaseModel):
    filename: str
    content_type: str = ""
    size_bytes: Optional[int] = None
    extension: str = ""


class AnalysisReport(BaseModel):
    score: int
    verdict: Verdict
    verdict_label: str
    disclaimer: str
    findings: list[Finding]
    urls: list[UrlPart]
    extracted_text: str = ""
    input_kind: str
    filename: Optional[str] = None
    filesize: Optional[int] = None
    upload_deleted: bool = False
    attachments: list[AttachmentMeta] = Field(default_factory=list)
    external_checks: list[ExternalCheck] = Field(default_factory=list)
    what_to_do: list[str]
    analyzed_at: str


class TextAnalyzeRequest(BaseModel):
    text: str = ""
    source_label: str = "pasted text"


class QuizAnswer(BaseModel):
    id: str
    question: str
    options: list[str]
    correct_index: int
    explanation: str
    sample: str
    is_phish: bool
