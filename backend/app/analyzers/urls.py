from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, unquote

from app.models import Finding, UrlPart

URL_RE = re.compile(
    r"(?i)\b((?:https?://)[^\s<>'\"\)\]]+|(?:www\.)[^\s<>'\"\)\]]+|(?:[a-z0-9-]+\.)+[a-z]{2,24}/[^\s<>'\"\)\]]*)"
)

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "tiny.cc",
    "rb.gy",
    "shorturl.at",
    "bl.ink",
    "lnkd.in",
    "s.id",
    "da.gd",
    "v.gd",
}

RISKY_TLDS = {
    "zip",
    "mov",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "xyz",
    "top",
    "click",
    "link",
    "country",
    "rest",
    "fit",
    "work",
    "cam",
    "loan",
    "win",
    "review",
    "accountants",
    "quest",
    "cfd",
    "sbs",
    "cyou",
}

MULTI_SUFFIXES = {
    "co.in",
    "org.in",
    "net.in",
    "gov.in",
    "ac.in",
    "edu.in",
    "res.in",
    "nic.in",
    "co.uk",
    "org.uk",
    "ac.uk",
    "com.au",
    "co.za",
}

BRANDS = {
    "sbi",
    "onlinesbi",
    "hdfc",
    "hdfcbank",
    "icici",
    "icicibank",
    "axisbank",
    "kotak",
    "pnb",
    "unionbank",
    "paytm",
    "phonepe",
    "googlepay",
    "gpay",
    "bhim",
    "npci",
    "upi",
    "irctc",
    "uidai",
    "aadhaar",
    "aadhar",
    "incometax",
    "gst",
    "epfo",
    "nsdl",
    "cibil",
    "amazon",
    "flipkart",
    "myntra",
    "whatsapp",
    "instagram",
    "facebook",
    "microsoft",
    "apple",
    "netflix",
    "naukri",
    "internshala",
    "linkedin",
    "rbi",
    "sbi",
}

ACCOUNT_WORDS = (
    "login",
    "signin",
    "verify",
    "verification",
    "update",
    "secure",
    "account",
    "kyc",
    "wallet",
    "reset",
    "password",
    "otp",
    "unlock",
    "confirm",
)

CONFUSABLES = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
    }
)


def extract_url_strings(text: str) -> list[str]:
    found: list[str] = []
    for match in URL_RE.findall(text or ""):
        raw = match.rstrip(".,;:!?)")
        if raw.lower().startswith("www."):
            raw = "http://" + raw
        elif "://" not in raw:
            raw = "http://" + raw
        found.append(raw)
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for item in found:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def registrable_domain(host: str) -> str:
    host = host.lower().rstrip(".")
    if not host:
        return ""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) < 2:
        return host
    last_two = ".".join(parts[-2:])
    last_three = ".".join(parts[-3:])
    if last_two in MULTI_SUFFIXES and len(parts) >= 3:
        return last_three
    if last_three in MULTI_SUFFIXES and len(parts) >= 4:
        return ".".join(parts[-4:])
    return last_two


def parse_url(url: str) -> UrlPart:
    split = urlsplit(url)
    host = (split.hostname or "").lower()
    is_ip = False
    try:
        if host:
            ipaddress.ip_address(host.strip("[]"))
            is_ip = True
    except ValueError:
        is_ip = False
    reg = host if is_ip else registrable_domain(host)
    subdomain = ""
    if host and reg and host.endswith(reg) and host != reg and not is_ip:
        subdomain = host[: -len(reg)].rstrip(".")
    return UrlPart(
        protocol=split.scheme or "",
        subdomain=subdomain,
        domain=reg,
        path=split.path or "",
        query=split.query or "",
        fragment=split.fragment or "",
        host=host,
        original=url,
        registrable_domain=reg,
        is_ip=is_ip,
        uses_https=split.scheme.lower() == "https",
    )


def _normalized_label(value: str) -> str:
    value = value.lower().translate(CONFUSABLES)
    return re.sub(r"[^a-z]", "", value)


def _lookalike_brand(domain: str) -> str | None:
    labels = domain.split(".")
    name = labels[0] if labels else domain
    compact = _normalized_label(name)
    if compact in BRANDS:
        # Exact brand as the domain name is fine only for well-known public suffixes
        # we cannot fully verify — skip if it is the brand itself with a common TLD
        return None
    for brand in BRANDS:
        if brand in compact and compact != brand:
            return brand
        # digit/letter swap distance-1 style: brand with extra hyphen words already caught
        if len(compact) >= 4 and abs(len(compact) - len(brand)) <= 2:
            if brand in compact or compact in brand:
                if compact != brand:
                    return brand
    # hyphenated brand-secure.tld
    for brand in BRANDS:
        if name.startswith(brand + "-") or name.endswith("-" + brand):
            return brand
    return None


def analyze_urls(urls: list[UrlPart]) -> list[Finding]:
    findings: list[Finding] = []
    for i, part in enumerate(urls):
        prefix = f"url-{i}"
        original = part.original
        decoded = unquote(original)

        if "@" in original.split("://", 1)[-1].split("/", 1)[0] or "@" in decoded:
            findings.append(
                Finding(
                    id=f"{prefix}-at",
                    title="Link uses an @ trick",
                    severity="high",
                    score_points=22,
                    explanation=(
                        "Everything before @ in a web address is ignored by the browser. "
                        "Scammers put a familiar name there so you never notice the real site after the @."
                    ),
                    lever="curiosity",
                    category="url",
                    evidence=original,
                )
            )

        if part.protocol and part.protocol.lower() != "https":
            findings.append(
                Finding(
                    id=f"{prefix}-http",
                    title="Link is not HTTPS",
                    severity="medium",
                    score_points=8,
                    explanation=(
                        "Legitimate banks and government sites in India use https:// (the lock). "
                        "A plain http:// page can be altered in transit and is a common lure."
                    ),
                    lever="none",
                    category="url",
                    evidence=original,
                )
            )

        if part.is_ip:
            findings.append(
                Finding(
                    id=f"{prefix}-ip",
                    title="Link uses a raw IP address",
                    severity="high",
                    score_points=20,
                    explanation=(
                        "Real organisations use a name like sbi.co.in, not a string of numbers. "
                        "An IP link often hides a throwaway server."
                    ),
                    lever="none",
                    category="url",
                    evidence=original,
                )
            )

        host = part.host
        if "xn--" in host:
            findings.append(
                Finding(
                    id=f"{prefix}-punycode",
                    title="Internationalized (punycode) domain",
                    severity="high",
                    score_points=24,
                    explanation=(
                        "This domain uses punycode (xn--). Attackers use look-alike letters from "
                        "other scripts so a fake site looks identical to a bank's name."
                    ),
                    lever="curiosity",
                    category="url",
                    evidence=original,
                )
            )

        if re.search(r"[^\x00-\x7F]", host):
            findings.append(
                Finding(
                    id=f"{prefix}-unicode",
                    title="Domain contains non-English letters",
                    severity="high",
                    score_points=22,
                    explanation=(
                        "Mixed or unusual scripts in a web address can impersonate a brand you trust. "
                        "Always type the official address yourself."
                    ),
                    lever="curiosity",
                    category="url",
                    evidence=original,
                )
            )

        reg = part.registrable_domain
        if reg in SHORTENERS or host in SHORTENERS:
            findings.append(
                Finding(
                    id=f"{prefix}-short",
                    title="Link shortener hides the real site",
                    severity="medium",
                    score_points=12,
                    explanation=(
                        "Short links (bit.ly, tinyurl, and similar) hide the destination. "
                        "Phishers use them so you cannot see a fake domain before you tap."
                    ),
                    lever="curiosity",
                    category="url",
                    evidence=original,
                )
            )

        tld = reg.split(".")[-1] if reg else ""
        if tld in RISKY_TLDS:
            findings.append(
                Finding(
                    id=f"{prefix}-tld",
                    title=f"Uncommon or risky domain ending (.{tld})",
                    severity="medium",
                    score_points=12,
                    explanation=(
                        f"Banks, UPI apps and government offices in India do not use .{tld} as their "
                        "main website. That ending is cheap and popular with throwaway scam sites."
                    ),
                    lever="none",
                    category="url",
                    evidence=original,
                )
            )

        brand = _lookalike_brand(reg or host)
        if brand:
            findings.append(
                Finding(
                    id=f"{prefix}-lookalike",
                    title=f"Look-alike of {brand}",
                    severity="high",
                    score_points=26,
                    explanation=(
                        f"The real site would be the official {brand} domain, not extra words, hyphens "
                        "or swapped digits. This pattern is used in fake KYC and UPI pages."
                    ),
                    lever="authority",
                    category="url",
                    evidence=original,
                )
            )

        haystack = f"{part.subdomain} {part.path} {part.query}".lower()
        if any(word in haystack for word in ACCOUNT_WORDS):
            findings.append(
                Finding(
                    id=f"{prefix}-account-words",
                    title="Link talks like a login or KYC page",
                    severity="medium",
                    score_points=8,
                    explanation=(
                        "Words such as login, verify, kyc or otp in a link are meant to feel official. "
                        "Open the real app instead of following a message link."
                    ),
                    lever="urgency",
                    category="url",
                    evidence=original,
                )
            )

        if re.search(r"\.apk(\b|$)", original, re.I) or "application/vnd.android" in original.lower():
            findings.append(
                Finding(
                    id=f"{prefix}-apk",
                    title="Link points to an APK download",
                    severity="high",
                    score_points=28,
                    explanation=(
                        "Banks never ask you to sideload an Android app from a chat. Fake APKs steal "
                        "SMS OTPs and empty UPI accounts."
                    ),
                    lever="fear",
                    category="url",
                    evidence=original,
                )
            )
    return findings
