# Phish Check

Working title: **PhishGuard**. A rule-based helper that scores whether an email, SMS, WhatsApp message, link or file looks like phishing or social engineering, explains why in plain language, and tells the user what to do next.

Built for the **Cybersecurity Challenge 2026** hackathon (Amity University Lucknow). Audience: Indian students and small-business users. India-specific lures covered include fake KYC, UPI/OTP fraud, “digital arrest” calls, fake jobs/scholarships, and QR-code scams.

A low score is **not** proof of safety. The engine is a transparent checklist, not a machine-learning classifier.

## What it does

1. **Text and URL analysis** — paste a message or link.
2. **Email upload** — `.eml` (Python `email` library) and `.msg` (read-only). SPF / DKIM / DMARC, From vs Reply-To vs Return-Path, Received hops. Attachments are **never opened or run**; only names and types are read.
3. **Screenshots and documents** — OCR on PNG/JPG via Tesseract; text extraction from PDF.
4. **Optional reputation** — Google Safe Browsing, VirusTotal, RDAP domain age. If a key is missing or a call fails, the UI shows **Not connected** or **Could not run**. Results are never faked. Each check lists its source and time.
5. **Awareness mode** — “Spot the phish” quiz plus a short explainer (social engineering vs phishing, common attacks, kill chain).

Uploads are written to a temp file, analysed, then **deleted**. The report says so.

## Quick start

You need **Python 3.11+** (3.14 is fine) and **Node.js 18+**. If `python` is not on PATH, use `py -3`.

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Optional screenshot OCR (Windows): install [Tesseract](https://github.com/UB-Mannheim/tesseract/wiki) and ensure `tesseract.exe` is on `PATH`. Without it, image uploads still work; OCR is marked **Could not run**.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. The Vite dev server proxies `/api` to the FastAPI app.

### Optional API keys

Copy `backend/.env.example` to `backend/.env`. Keys stay on the server.

| Variable | Used for |
| --- | --- |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Safe Browsing v4 `threatMatches:find` |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 URL lookup |

RDAP (domain age) needs no key: `https://rdap.org/domain/{domain}`.

Leave keys blank for a demo. External checks will show **Not connected**.

### Sample email file

`backend/samples/fake_kyc.eml` is a synthetic SBI KYC phish with failing SPF/DKIM/DMARC, mismatched Reply-To, and a double-extension APK. Upload it from the UI (do not open the “attachment”).

On the home screen, **Load sample** offers a fake bank KYC SMS, a look-alike payment link, and a digital-arrest script.

## Scoring

Findings add points (capped at 100).

- **0–29** Low risk — still verify
- **30–59** Suspicious
- **60–100** High risk

Critical combinations (digital arrest, remote-access apps, OTP harvest, dangerous attachments) raise the floor to 70. Each finding names the **psychological lever** (urgency, fear, authority, greed, curiosity).

## Limitations and future work

- Rules miss novel wording, homoglyphs we do not list, and well-spoofed mail that still passes SPF/DKIM.
- OCR depends on screenshot quality and a local Tesseract install.
- Reputation APIs are optional, rate-limited, and can lag behind brand-new sites.
- We do not sandbox detonate files, follow redirects on shorteners, or talk to a live mailbox.

Useful next steps: a small **ML classifier** trained on Indian scam SMS (with the rules kept as explanations), richer **threat-intel feeds**, a **browser extension** that highlights the registrable domain before click, and multilingual (Hindi) copy.

## Privacy

Do not upload real passwords, OTPs or financial documents. Analysis is local to your machine unless you enable Safe Browsing / VirusTotal, which then receive the submitted URLs only.

## Stack

React (Vite) + FastAPI. Dark mode, keyboard-visible focus, and a visual URL breakdown (protocol / subdomain / **real domain** / path).
