from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from app.analyzers.attachments import inspect_attachment_name
from app.analyzers.email_msg import parse_eml_bytes, parse_msg_file
from app.analyzers.ocr import extract_pdf_text, ocr_image
from app.analyzers.reputation import run_reputation
from app.analyzers.text import analyze_text
from app.analyzers.urls import analyze_urls, extract_url_strings, parse_url
from app.models import AnalysisReport, AttachmentMeta, Finding
from app.scoring import DISCLAIMER, WHAT_TO_DO, score_and_verdict, sort_findings

IMAGE_EXT = {".png", ".jpg", ".jpeg"}


def analyze_bundle(
    text: str,
    *,
    input_kind: str,
    filename: str | None = None,
    filesize: int | None = None,
    extra_findings: list[Finding] | None = None,
    attachments: list[AttachmentMeta] | None = None,
    upload_deleted: bool = False,
    skip_reputation: bool = False,
) -> AnalysisReport:
    extra_findings = extra_findings or []
    attachments = attachments or []
    urls = [parse_url(item) for item in extract_url_strings(text)]
    findings: list[Finding] = []
    findings.extend(extra_findings)
    findings.extend(analyze_text(text))
    findings.extend(analyze_urls(urls))
    checks = []
    if not skip_reputation:
        rep_findings, checks = run_reputation(urls)
        findings.extend(rep_findings)
    findings = sort_findings(findings)
    score, verdict, label = score_and_verdict(findings)
    return AnalysisReport(
        score=score,
        verdict=verdict,
        verdict_label=label,
        disclaimer=DISCLAIMER,
        findings=findings,
        urls=urls,
        extracted_text=text[:8000],
        input_kind=input_kind,
        filename=filename,
        filesize=filesize,
        upload_deleted=upload_deleted,
        attachments=attachments,
        external_checks=checks,
        what_to_do=WHAT_TO_DO,
        analyzed_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def analyze_file(path: Path, original_name: str, size: int) -> AnalysisReport:
    ext = Path(original_name).suffix.lower()
    extra: list[Finding] = inspect_attachment_name(original_name)
    attachments: list[AttachmentMeta] = []
    text = ""
    kind = "file"

    try:
        if ext == ".eml":
            kind = "email"
            text, email_findings, attachments = parse_eml_bytes(path.read_bytes())
            extra.extend(email_findings)
        elif ext == ".msg":
            kind = "email"
            text, email_findings, attachments = parse_msg_file(path)
            extra.extend(email_findings)
        elif ext == ".txt":
            kind = "text-file"
            text = path.read_text(encoding="utf-8", errors="replace")
        elif ext == ".pdf":
            kind = "pdf"
            text, pdf_findings = extract_pdf_text(path)
            extra.extend(pdf_findings)
        elif ext in IMAGE_EXT:
            kind = "screenshot"
            text, ocr_findings = ocr_image(path)
            extra.extend(ocr_findings)
        else:
            kind = "unsupported"
            extra.append(
                Finding(
                    id="file-unsupported",
                    title="File type was not analysed as a message",
                    severity="info",
                    score_points=0,
                    explanation=(
                        "Use .eml, .msg, .txt, .pdf or a PNG/JPG screenshot. "
                        "Attachments are never opened or run."
                    ),
                    category="attachment",
                )
            )
    finally:
        deleted = False
        try:
            os.remove(path)
            deleted = True
        except OSError:
            deleted = False

    return analyze_bundle(
        text,
        input_kind=kind,
        filename=original_name,
        filesize=size,
        extra_findings=extra,
        attachments=attachments,
        upload_deleted=deleted,
    )
