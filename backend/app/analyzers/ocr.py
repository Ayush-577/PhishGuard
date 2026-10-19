from __future__ import annotations

from pathlib import Path

from app.models import Finding

# Initialize EasyOCR reader outside the function so it loads once globally
try:
    import easyocr
    reader = easyocr.Reader(['en'], gpu=False)  # Explicitly disable GPU for free tier servers
except ImportError:
    reader = None


def ocr_image(path: Path) -> tuple[str, list[Finding]]:
    findings: list[Finding] = []
    
    if reader is None:
        findings.append(
            Finding(
                id="ocr-unavailable",
                title="OCR libraries are not installed",
                severity="info",
                score_points=0,
                explanation="Could not run screenshot reading because Python easyocr packages are missing or failed to import.",
                category="ocr",
            )
        )
        return "", findings

    try:
        from PIL import Image, ImageOps
        import numpy as np
        
        # Load and fix image orientation
        image = Image.open(path)
        image = ImageOps.exif_transpose(image)
        if image.mode not in {"RGB", "L"}:
            image = image.convert("RGB")
            
        # Convert PIL image to an array EasyOCR can read
        image_np = np.array(image)
        
        # Execute OCR scan
        results = reader.readtext(image_np)
        
        # Combine all extracted lines into a clean string layout
        text = " ".join([item[1] for item in results]) or ""
        
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
        reader_pdf = PdfReader(str(path))
        if getattr(reader_pdf, "is_encrypted", False):
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
        for page in reader_pdf.pages[:15]:
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
