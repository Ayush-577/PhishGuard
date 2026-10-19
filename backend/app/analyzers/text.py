from __future__ import annotations

import re

from app.models import Finding

Rule = tuple[str, str, str, int, str, str, str]

RULES: list[Rule] = [
    (
        "digital-arrest",
        r"\bdigital\s*arrest\b|\bunder\s+arrest\b|\bcourt\s+escrow\b|\bremand\b|\bwarrant\s+issued\b",
        "Mentions digital arrest or a fake court case",
        30,
        "high",
        "fear",
        "There is no such thing as a 'digital arrest' over a phone or video call. "
        "Cybercriminals pose as police or CBI, keep you on a call, and demand money. Hang up.",
    ),
    (
        "remote-access",
        r"\banydesk\b|\bteamviewer\b|\bultraviewer\b|\bquick\s*support\b|\bremote\s+(access|desktop|support)\b|\bscreen\s*share\b",
        "Asks you to install a remote-access app",
        28,
        "high",
        "authority",
        "Banks, police and tax officers will never ask you to install AnyDesk or TeamViewer. "
        "Once they see your screen they can approve UPI payments and empty accounts.",
    ),
    (
        "otp-request",
        r"\b(otp|one[-\s]*time\s*(password|pin)|cvv|atm\s*pin|upi\s*pin|internet\s*banking\s*password)\b"
        r".{0,40}\b(share|send|tell|give|forward|confirm)\b|"
        r"\b(share|send|tell|give|forward|confirm)\b.{0,40}"
        r"\b(otp|one[-\s]*time\s*(password|pin)|cvv|atm\s*pin|upi\s*pin)\b|"
        r"\benter\s+(your\s+)?otp\b|\bprovide\s+(your\s+)?(otp|pin|password)\b",
        "Asks for OTP, PIN or password",
        26,
        "high",
        "authority",
        "An OTP is meant only for you. Nobody from a bank, WhatsApp or 'cyber cell' needs it. "
        "Sharing it lets them take money immediately.",
    ),
    (
        "kyc-lure",
        r"\b(re-?kyc|video\s*kyc|v-?kyc|update\s+kyc|kyc\s+(pending|expired|incomplete|update))\b|"
        r"\baadhaar\s+(kyc|link|update)\b|\bpan\s+(kyc|update)\b",
        "Fake KYC or Aadhaar update lure",
        18,
        "high",
        "fear",
        "Banks ask for KYC inside their official app or branch — not through a random SMS link. "
        "Fake KYC pages copy the bank logo and steal login details.",
    ),
    (
        "account-blocked",
        r"\b(account|wallet|upi|debit\s*card|credit\s*card).{0,24}\b(block|blocked|suspend|frozen|deactivat)|"
        r"\b(will be|shall be|is being)\s+(blocked|suspended|frozen)\b",
        "Threatens a blocked or frozen account",
        16,
        "high",
        "fear",
        "Fear of a blocked account makes people tap without thinking. If you are worried, open "
        "the bank's own app from your phone home screen — never from this message.",
    ),
    (
        "urgency",
        r"\b(immediately|urgent|right now|act now|within\s+\d+\s*(hour|hr|minute|min|day)s?|"
        r"last chance|expire[sd]?|final (notice|warning)|limited time)\b",
        "Uses extreme urgency",
        10,
        "medium",
        "urgency",
        "Scams shrink your thinking time: '24 hours', 'immediately', 'last chance'. Real "
        "institutions give you time and a way to verify through official channels.",
    ),
    (
        "prize-refund",
        r"\b(lottery|jackpot|you have won|congratulations.{0,20}won|lucky winner|"
        r"cashback|refund\s+(of|rs|inr)|claim\s+(your\s+)?(prize|reward|refund)|"
        r"scholarship\s+(granted|awarded|selected))\b",
        "Dangles a prize, refund or scholarship",
        14,
        "medium",
        "greed",
        "Unexpected prizes, refunds and 'you are selected' scholarships are bait. You will be "
        "asked to pay a fee or share UPI / OTP to 'receive' money that does not exist.",
    ),
    (
        "job-offer",
        r"\b(work from home|part[-\s]*time job|data entry job|selected for interview|"
        r"registration fee|joining fee|training fee).{0,30}\b(pay|upi|rs|inr)\b|"
        r"\b(pay|deposit).{0,20}(registration|joining|training)\s+fee\b",
        "Job offer that asks for money",
        16,
        "high",
        "greed",
        "Genuine employers do not ask students to pay a registration or training fee over "
        "WhatsApp. Fake job and internship offers are a common campus scam.",
    ),
    (
        "money-request",
        r"\b(transfer|send|deposit|pay)\b.{0,40}\b(rs\.?|inr|₹)\s*\d|"
        r"\b(rs\.?|inr|₹)\s*\d.{0,40}\b(transfer|send|deposit|pay)\b|"
        r"\bupi\s*(id)?\b.{0,20}@|"
        r"\bcollect request\b|\bpay the (fine|penalty|bail|escrow)\b",
        "Asks you to send money",
        18,
        "high",
        "fear",
        "A message that tells you to transfer rupees, pay 'bail', or honour a UPI collect "
        "request is trying to move money before you can think. Pause and call a trusted person.",
    ),
    (
        "qr-code",
        r"\bqr\s*code\b|\bscan\s+(this|the|my)\s+qr\b|\bscan\s+to\s+(receive|pay|verify|kyc)\b",
        "Asks you to scan a QR code",
        12,
        "medium",
        "curiosity",
        "A QR code can be a payment request, not a refund. Scanning a stranger's QR from a "
        "chat can send your money the other way.",
    ),
    (
        "authority-impersonation",
        r"\b(cyber\s*cell|cyber\s*crime|cbi|ed\b|enforcement directorate|rbi\b|income\s*tax|"
        r"uidai|police\s+station|acp\b|dcp\b|sp\b|reserve bank)\b",
        "Claims to be police, RBI, tax or cyber cell",
        14,
        "medium",
        "authority",
        "Officials do not threaten citizens on WhatsApp or demand money on a video call. "
        "If in doubt, hang up and call 1930 or visit cybercrime.gov.in.",
    ),
    (
        "secrecy",
        r"\bdo not tell\b|\bdon't tell anyone\b|\bkeep this (call )?confidential\b|"
        r"\bdo not disconnect\b|\bstay on the (call|line)\b",
        "Tells you to stay silent or stay on the line",
        12,
        "medium",
        "fear",
        "Isolation is a classic social-engineering trick. Anyone who forbids you from hanging "
        "up or talking to family is not a real officer.",
    ),
]


def analyze_text(text: str) -> list[Finding]:
    if not text or not text.strip():
        return []
    blob = text
    findings: list[Finding] = []
    for rule_id, pattern, title, points, severity, lever, explanation in RULES:
        match = re.search(pattern, blob, flags=re.IGNORECASE | re.DOTALL)
        if not match:
            continue
        snippet = match.group(0)
        findings.append(
            Finding(
                id=f"text-{rule_id}",
                title=title,
                severity=severity,  # type: ignore[arg-type]
                score_points=points,
                explanation=explanation,
                lever=lever,  # type: ignore[arg-type]
                category="text",
                evidence=snippet[:240],
            )
        )
    return findings
