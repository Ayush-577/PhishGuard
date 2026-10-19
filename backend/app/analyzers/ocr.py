from __future__ import annotations

from pathlib import Path

from app.models import Finding


def ocr_image(path: Path) -> tuple[str, list[Finding]]:
    findings: list[Finding] = []
    try:
        from PIL import Image, ImageOps
        import pytesseract
    except ImportError:
        findings.append(
            Finding(
                id="ocr-unavailable",
                title="OCR libraries are not installed",
                severity="info",
                score_points=0,
                explanation="Could not run screenshot reading because Python OCR packages are missing.",
                category="ocr",
            )
        )
        return "", findings

    try:
        image = Image.open(path)
        image = ImageOps.exif_transpose(image)
        if image.mode not in {"RGB", "L"}:
            image = image.convert("RGB")
        text = pytesseract.image_to_string(image) or ""
        if not text.strip():
            findings.append(
                Finding(
                    id="ocr-empty",
                    title="No readable text in the screenshot",
                    severity="info",
                    score_points=0,
                    explanation=(
                        "We ran OCR but found little or no text. A cropped or blurry screenshot is "
                        "hard to read — you can also paste the message text."
                    ),
                    category="ocr",
                )
            )
        return text, findings
    except pytesseract.TesseractNotFoundError:
        findings.append(
            Finding(
                id="ocr-tesseract-missing",
                title="Could not run screenshot OCR",
                severity="info",
                score_points=0,
                explanation=(
                    "Tesseract is not installed on this computer. Paste the message text, or install "
                    "Tesseract and try the screenshot again. We did not invent any OCR results."
                ),
                category="ocr",
            )
        )
        return "", findings
    except Exception as exc:
        findings.append(
            Finding(
                id="ocr-failed",
                title="Could not run screenshot OCR",
                severity="info",
                score_points=0,
                explanation=f"OCR failed ({type(exc).__name__}). Paste the text instead. No fake result was generated.",
                category="ocr",
            )
        )
        return "", findings


def extract_pdf_text(path: Path) -> tuple[str, list[Finding]]:
    findings: list[Finding] = []
    try:
        from pypdf import PdfReader
    except ImportError:
        return "", [
            Finding(
                id="pdf-lib-missing",
                title="Could not read PDF text",
                severity="info",
                score_points=0,
                explanation="The PDF library is not installed on this server.",
                category="attachment",
            )
        ]
    try:
        reader = PdfReader(str(path))
        if getattr(reader, "is_encrypted", False):
            findings.append(
                Finding(
                    id="pdf-encrypted",
                    title="Password-protected PDF (not opened)",
                    severity="medium",
                    score_points=10,
                    explanation=(
                        "This PDF is encrypted. Attackers lock files so scanners cannot read them. "
                        "We did not try to decrypt or run anything inside it."
                    ),
                    lever="curiosity",
                    category="attachment",
                )
            )
            return "", findings
        chunks: list[str] = []
        for page in reader.pages[:15]:
            chunks.append(page.extract_text() or "")
        return "\n".join(chunks), findings
    except Exception as exc:
        findings.append(
            Finding(
                id="pdf-failed",
                title="Could not read PDF text",
                severity="info",
                score_points=0,
                explanation=f"PDF parsing failed ({type(exc).__name__}). We never execute PDF scripts or attachments.",
                category="attachment",
            )
        )
        return "", findings
