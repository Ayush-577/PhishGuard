from __future__ import annotations

import email
import re
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr
from pathlib import Path
from typing import Optional

from app.analyzers.attachments import inspect_attachment_name
from app.models import AttachmentMeta, Finding

AUTH_RE = re.compile(
    r"(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
    re.IGNORECASE,
)


def _domain_of(address: str) -> str:
    _, addr = parseaddr(address or "")
    if "@" not in addr:
        return ""
    return addr.split("@", 1)[1].strip().lower().strip(">")


def parse_eml_bytes(data: bytes) -> tuple[str, list[Finding], list[AttachmentMeta]]:
    msg = email.message_from_bytes(data, policy=policy.default)
    return _from_message(msg)


def parse_msg_file(path: Path) -> tuple[str, list[Finding], list[AttachmentMeta]]:
    try:
        import extract_msg  # type: ignore
    except ImportError:
        return (
            "",
            [
                Finding(
                    id="email-msg-unavailable",
                    title="Could not read Outlook .msg file",
                    severity="info",
                    score_points=0,
                    explanation="The optional Outlook parser is not installed on this server.",
                    category="email",
                )
            ],
            [],
        )
    message = extract_msg.Message(str(path))
    try:
        body = (message.body or "") + "\n" + (message.htmlBody or "")
        headers = message.header_dict or {}
        findings: list[Finding] = []
        from_addr = str(headers.get("From", message.sender or ""))
        reply_to = str(headers.get("Reply-To", ""))
        return_path = str(headers.get("Return-Path", ""))
        findings.extend(_address_mismatch(from_addr, reply_to, return_path))
        attachments: list[AttachmentMeta] = []
        for att in message.attachments or []:
            name = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or "attachment"
            meta = AttachmentMeta(filename=str(name), extension=Path(str(name)).suffix.lower())
            attachments.append(meta)
            findings.extend(inspect_attachment_name(meta.filename))
        subject = message.subject or ""
        text = f"Subject: {subject}\nFrom: {from_addr}\n\n{body}"
        return text, findings, attachments
    finally:
        try:
            message.close()
        except Exception:
            pass


def _from_message(msg: EmailMessage | email.message.Message) -> tuple[str, list[Finding], list[AttachmentMeta]]:
    findings: list[Finding] = []
    from_addr = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))
    subject = str(msg.get("Subject", ""))
    findings.extend(_address_mismatch(from_addr, reply_to, return_path))
    findings.extend(_auth_results(str(msg.get("Authentication-Results", "")), str(msg.get("Received-SPF", ""))))
    findings.extend(_received_hops(msg.get_all("Received") or []))

    attachments: list[AttachmentMeta] = []
    body_parts: list[str] = [f"Subject: {subject}", f"From: {from_addr}", ""]

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()
            if filename:
                meta = AttachmentMeta(
                    filename=filename,
                    content_type=ctype,
                    extension=Path(filename).suffix.lower(),
                )
                attachments.append(meta)
                findings.extend(inspect_attachment_name(filename, ctype))
                continue
            if ctype == "text/plain" and "attachment" not in disp.lower():
                payload = part.get_payload(decode=True) or b""
                body_parts.append(_decode(payload, part.get_content_charset()))
            elif ctype == "text/html" and "attachment" not in disp.lower():
                payload = part.get_payload(decode=True) or b""
                html = _decode(payload, part.get_content_charset())
                body_parts.append(_strip_html(html))
    else:
        payload = msg.get_payload(decode=True) or b""
        body_parts.append(_decode(payload, msg.get_content_charset()))

    return "\n".join(body_parts), findings, attachments


def _decode(payload: bytes, charset: Optional[str]) -> str:
    for enc in (charset, "utf-8", "latin-1"):
        if not enc:
            continue
        try:
            return payload.decode(enc, errors="replace")
        except LookupError:
            continue
    return payload.decode("utf-8", errors="replace")


def _strip_html(html: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _address_mismatch(from_addr: str, reply_to: str, return_path: str) -> list[Finding]:
    findings: list[Finding] = []
    from_d = _domain_of(from_addr)
    reply_d = _domain_of(reply_to)
    return_d = _domain_of(return_path)
    if from_d and reply_d and from_d != reply_d:
        findings.append(
            Finding(
                id="email-reply-to-mismatch",
                title="From and Reply-To domains do not match",
                severity="high",
                score_points=18,
                explanation=(
                    f"The message looks like it comes from {from_d}, but replies would go to {reply_d}. "
                    "Phishers display a trusted name and harvest replies on their own mailbox."
                ),
                lever="authority",
                category="email",
                evidence=f"From: {from_addr} | Reply-To: {reply_to}",
            )
        )
    if from_d and return_d and from_d != return_d:
        findings.append(
            Finding(
                id="email-return-path-mismatch",
                title="From and Return-Path domains do not match",
                severity="medium",
                score_points=12,
                explanation=(
                    f"Bounce messages would go to {return_d}, not {from_d}. That often means the "
                    "visible sender is spoofed."
                ),
                lever="authority",
                category="email",
                evidence=f"From: {from_addr} | Return-Path: {return_path}",
            )
        )
    display, addr = parseaddr(from_addr)
    if display and addr and _domain_of(display) and _domain_of(display) != _domain_of(addr):
        findings.append(
            Finding(
                id="email-display-spoof",
                title="Display name pretends to be another organisation",
                severity="medium",
                score_points=10,
                explanation=(
                    "The friendly name shows one company while the actual address is different. "
                    "Always expand the sender to see the real email address."
                ),
                lever="authority",
                category="email",
                evidence=from_addr,
            )
        )
    return findings


def _auth_results(auth_header: str, received_spf: str) -> list[Finding]:
    findings: list[Finding] = []
    blob = f"{auth_header} {received_spf}"
    results = {k.lower(): v.lower() for k, v in AUTH_RE.findall(blob)}
    if not blob.strip():
        findings.append(
            Finding(
                id="email-auth-missing",
                title="No SPF / DKIM / DMARC results in the headers",
                severity="low",
                score_points=4,
                explanation=(
                    "This file has no Authentication-Results line. That can happen with forwarded "
                    "mail. We cannot prove the sender is genuine from headers alone."
                ),
                lever="none",
                category="email",
            )
        )
        return findings
    for mech, meaning, points in (
        ("spf", "SPF", 14),
        ("dkim", "DKIM", 14),
        ("dmarc", "DMARC", 18),
    ):
        value = results.get(mech)
        if value in {"fail", "softfail", "permerror"}:
            findings.append(
                Finding(
                    id=f"email-{mech}-fail",
                    title=f"{meaning} check did not pass ({value})",
                    severity="high" if mech == "dmarc" or value == "fail" else "medium",
                    score_points=points,
                    explanation=(
                        f"{meaning} is how receiving servers ask: 'is this mail really from that domain?' "
                        f"A result of {value} is a strong sign of spoofing."
                    ),
                    lever="authority",
                    category="email",
                    evidence=blob[:300],
                )
            )
    return findings


def _received_hops(hops: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    if len(hops) >= 10:
        findings.append(
            Finding(
                id="email-many-hops",
                title="Unusually long Received chain",
                severity="low",
                score_points=4,
                explanation=(
                    f"This message lists {len(hops)} Received hops. Long chains can be normal for "
                    "forwarding, but they also hide the original source."
                ),
                lever="none",
                category="email",
            )
        )
    joined = "\n".join(hops).lower()
    if re.search(r"from\s+\d+\.\d+\.\d+\.\d+", joined) and "localhost" not in joined:
        findings.append(
            Finding(
                id="email-ip-hop",
                title="A Received hop shows a raw IP",
                severity="low",
                score_points=3,
                explanation=(
                    "One server in the path identified itself only by IP address. Combine this with "
                    "other header mismatches before you trust the sender."
                ),
                lever="none",
                category="email",
            )
        )
    return findings
