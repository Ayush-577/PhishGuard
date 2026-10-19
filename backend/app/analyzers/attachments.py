from __future__ import annotations

from pathlib import Path

from app.models import Finding

RISKY_EXT = {
    ".exe",
    ".apk",
    ".msi",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".vbs",
    ".ps1",
    ".jar",
    ".html",
    ".htm",
    ".hta",
    ".iso",
    ".img",
    ".dll",
    ".com",
    ".pif",
}

MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".doc", ".xls"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".iso"}
DOUBLE_FIRST = {".pdf", ".jpg", ".jpeg", ".png", ".txt", ".docx", ".xlsx", ".doc", ".xls"}


def inspect_attachment_name(filename: str, content_type: str = "") -> list[Finding]:
    findings: list[Finding] = []
    name = filename or "attachment"
    path = Path(name)
    suffixes = [s.lower() for s in path.suffixes]
    ext = path.suffix.lower()

    if ext in RISKY_EXT or any(s in RISKY_EXT for s in suffixes):
        findings.append(
            Finding(
                id=f"att-risky-{name}",
                title=f"Risky file type: {name}",
                severity="high",
                score_points=24,
                explanation=(
                    "This file type can install software or open a fake login page. Phish Check never "
                    "opens or runs attachments — it only reads the name and type. Do not open it."
                ),
                lever="curiosity",
                category="attachment",
                evidence=f"{name} ({content_type})",
            )
        )
    if ext in MACRO_EXT:
        findings.append(
            Finding(
                id=f"att-macro-{name}",
                title="Office file that may contain macros",
                severity="high",
                score_points=20,
                explanation=(
                    "Macro-enabled or older Office files are a classic way to run code when you click "
                    "Enable Content. Banks do not send you spreadsheets to 'unlock' an account."
                ),
                lever="authority",
                category="attachment",
                evidence=name,
            )
        )
    if len(suffixes) >= 2 and suffixes[-2] in DOUBLE_FIRST and suffixes[-1] in RISKY_EXT | {".html", ".htm", ".exe", ".apk"}:
        findings.append(
            Finding(
                id=f"att-double-{name}",
                title="Double extension hides the real file type",
                severity="high",
                score_points=22,
                explanation=(
                    f"The name looks like {''.join(suffixes[:-1])} but actually ends with {suffixes[-1]}. "
                    "Windows may hide the last extension so a program looks like a PDF."
                ),
                lever="curiosity",
                category="attachment",
                evidence=name,
            )
        )
    if ext in ARCHIVE_EXT:
        findings.append(
            Finding(
                id=f"att-archive-{name}",
                title="Archive attachment (not opened)",
                severity="low",
                score_points=4,
                explanation=(
                    "Zip and similar archives can hide malware. If the sender also asked you to use a "
                    "password, that is so antivirus cannot scan it. We did not unpack this file."
                ),
                lever="curiosity",
                category="attachment",
                evidence=name,
            )
        )
    lower = name.lower()
    if "password" in lower or "passwd" in lower or "pwd" in lower:
        findings.append(
            Finding(
                id=f"att-pwd-name-{name}",
                title="Attachment name mentions a password",
                severity="medium",
                score_points=8,
                explanation=(
                    "Password-protected archives are often used so scanners cannot look inside. "
                    "Do not extract it."
                ),
                lever="curiosity",
                category="attachment",
                evidence=name,
            )
        )
    return findings
