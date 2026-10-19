from __future__ import annotations

from app.config import LOW_MAX, SUSPICIOUS_MAX
from app.models import Finding, Verdict

DISCLAIMER = (
    "Phish Check is a rule-based helper, not a verdict from a human analyst. "
    "A low score is not proof that a message is safe. When in doubt, do not click, "
    "do not share an OTP, and verify through the official app or phone number you already have."
)

WHAT_TO_DO = [
    "Do not tap the link, scan the QR, or open the attachment.",
    "Do not share OTP, UPI PIN, CVV, passwords, or remote-access codes. Banks and police never ask for these.",
    "Verify using the official app or the phone number printed on your card / the organisation's website — not a number from this message.",
    "Report phishing at cybercrime.gov.in or call 1930 (India Citizen Financial Cyber Fraud Helpline).",
    "If you already paid, shared an OTP, or installed AnyDesk, call your bank's official helpline immediately and then report at 1930.",
]

LEVER_ORDER = {"fear": 0, "urgency": 1, "authority": 2, "greed": 3, "curiosity": 4, "none": 5}
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def score_and_verdict(findings: list[Finding]) -> tuple[int, Verdict, str]:
    score = 0
    for item in findings:
        score += max(0, item.score_points)
    critical = any(
        item.id.startswith(("text-digital-arrest", "text-remote-access", "text-otp-request"))
        or "apk" in item.id
        or (item.category == "attachment" and item.severity == "high")
        for item in findings
    )
    if critical:
        score = max(score, 70)
    score = min(100, score)
    if score <= LOW_MAX:
        return score, "low", "Low risk — still verify, do not treat this as a green light"
    if score <= SUSPICIOUS_MAX:
        return score, "suspicious", "Suspicious — pause and verify through official channels"
    return score, "high", "High risk — treat this as a likely scam"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEV_ORDER.get(f.severity, 9), -f.score_points, f.title),
    )
