from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import ALLOWED_EXTENSIONS, MAX_UPLOAD_BYTES
from app.models import TextAnalyzeRequest
from app.pipeline import analyze_bundle, analyze_file
from app.samples_data import QUIZ, SAMPLES

app = FastAPI(
    title="Phish Check",
    description="Rule-based phishing and social-engineering helper for students and small businesses.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"ok": True, "name": "Phish Check"}


@app.post("/api/analyze/text")
def analyze_text_endpoint(body: TextAnalyzeRequest):
    text = (body.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Paste a message or URL first.")
    if len(text) > 50_000:
        raise HTTPException(status_code=400, detail="Text is too long (50,000 character limit).")
    return analyze_bundle(text, input_kind=body.source_label or "pasted text")


@app.post("/api/analyze/file")
async def analyze_file_endpoint(file: UploadFile = File(...)):
    name = file.filename or "upload"
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Allowed types: .eml, .msg, .txt, .pdf, .png, .jpg, .jpeg",
        )
    data = await file.read()
    size = len(data)
    if size == 0:
        raise HTTPException(status_code=400, detail="The file is empty.")
    if size > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="File is larger than 10 MB.")
    suffix = ext or ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)
    return analyze_file(tmp_path, name, size)


@app.get("/api/samples")
def list_samples():
    return {"samples": list(SAMPLES.values())}


@app.post("/api/samples/{sample_id}")
def analyze_sample(sample_id: str):
    sample = SAMPLES.get(sample_id)
    if not sample:
        raise HTTPException(status_code=404, detail="Unknown sample.")
    return analyze_bundle(sample["text"], input_kind=f"sample:{sample['title']}")


@app.get("/api/learn/quiz")
def quiz():
    return {"questions": QUIZ}


@app.get("/api/learn/explainer")
def explainer():
    return {
        "title": "The human layer",
        "sections": [
            {
                "heading": "Social engineering vs phishing",
                "body": (
                    "Social engineering is any trick that makes a person help an attacker — over a call, "
                    "a chat, a QR code or a visit. Phishing is the subset that uses a fake message or "
                    "website to steal secrets (passwords, OTPs) or to plant malware. Both target trust, "
                    "not firewalls."
                ),
            },
            {
                "heading": "Common attacks in India",
                "body": (
                    "Fake KYC and 'account blocked' SMS, UPI collect / OTP fraud, digital-arrest video "
                    "calls, fake jobs and scholarships, look-alike bank sites, and QR codes that send "
                    "money instead of receiving it. Remote-access apps (AnyDesk, TeamViewer) turn a "
                    "phone call into a full takeover."
                ),
            },
            {
                "heading": "A simple kill chain",
                "body": (
                    "You can break the chain at the first two steps: do not react on the attacker's "
                    "clock, and never follow a path they built. Use channels you already trust."
                ),
                "steps": [
                    "Bait — a message that creates fear, greed or urgency.",
                    "Hook — a link, QR, APK or remote-access app.",
                    "Harvest — OTP, PIN, session cookie or screen control.",
                    "Cash-out — UPI transfer, card drain, or more lures from your contacts.",
                    "Cover — throwaway domains and SIM cards disappear in days.",
                ],
            },
        ],
    }


FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="ui")
