from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from app.config import GOOGLE_SAFE_BROWSING_API_KEY, VIRUSTOTAL_API_KEY
from app.models import ExternalCheck, Finding, UrlPart

TIMEOUT = 8.0


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def run_reputation(urls: list[UrlPart]) -> tuple[list[Finding], list[ExternalCheck]]:
    findings: list[Finding] = []
    checks: list[ExternalCheck] = []
    unique_urls = []
    seen: set[str] = set()
    for part in urls:
        key = part.original.lower()
        if key in seen:
            continue
        seen.add(key)
        unique_urls.append(part)
        if len(unique_urls) >= 5:
            break

    checks.append(_safe_browsing(unique_urls, findings))
    checks.append(_virustotal(unique_urls, findings))
    checks.extend(_rdap_ages(unique_urls, findings))
    return findings, checks


def _safe_browsing(urls: list[UrlPart], findings: list[Finding]) -> ExternalCheck:
    source = "Google Safe Browsing API v4 (threatMatches:find)"
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return ExternalCheck(
            name="Google Safe Browsing",
            status="not_connected",
            source=source,
            summary="Not connected — no GOOGLE_SAFE_BROWSING_API_KEY in the server environment.",
        )
    if not urls:
        return ExternalCheck(
            name="Google Safe Browsing",
            status="skipped",
            source=source,
            checked_at=_now(),
            summary="No URLs to look up.",
        )
    body = {
        "client": {"clientId": "phish-check", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u.original} for u in urls],
        },
    }
    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    )
    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.post(endpoint, json=body)
        if response.status_code >= 400:
            return ExternalCheck(
                name="Google Safe Browsing",
                status="could_not_run",
                source=source,
                checked_at=_now(),
                summary=f"Could not run — HTTP {response.status_code}.",
                details={"status_code": response.status_code},
            )
        data = response.json() if response.content else {}
        matches = data.get("matches") or []
        if matches:
            sample = matches[0]
            findings.append(
                Finding(
                    id="rep-gsb-hit",
                    title="Google Safe Browsing flagged a link",
                    severity="high",
                    score_points=30,
                    explanation=(
                        "Google's Safe Browsing list currently marks at least one URL as malware or "
                        "social engineering. Treat it as dangerous even if the message looks official."
                    ),
                    lever="none",
                    category="reputation",
                    evidence=str(sample.get("threat", {})),
                )
            )
            summary = f"Unsafe — {len(matches)} match(es)."
        else:
            summary = "No matches for the submitted URLs (this is not a guarantee of safety)."
        return ExternalCheck(
            name="Google Safe Browsing",
            status="ok",
            source=source,
            checked_at=_now(),
            summary=summary,
            details={"match_count": len(matches)},
        )
    except Exception as exc:
        return ExternalCheck(
            name="Google Safe Browsing",
            status="could_not_run",
            source=source,
            checked_at=_now(),
            summary=f"Could not run — {type(exc).__name__}.",
        )


def _virustotal(urls: list[UrlPart], findings: list[Finding]) -> ExternalCheck:
    source = "VirusTotal API v3 (POST /urls, GET /analyses)"
    if not VIRUSTOTAL_API_KEY:
        return ExternalCheck(
            name="VirusTotal",
            status="not_connected",
            source=source,
            summary="Not connected — no VIRUSTOTAL_API_KEY in the server environment.",
        )
    if not urls:
        return ExternalCheck(
            name="VirusTotal",
            status="skipped",
            source=source,
            checked_at=_now(),
            summary="No URLs to look up.",
        )
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    flagged = 0
    errors = 0
    details: dict[str, int] = {}
    try:
        with httpx.Client(timeout=TIMEOUT, headers=headers) as client:
            for part in urls[:3]:
                submit = client.post("https://www.virustotal.com/api/v3/urls", data={"url": part.original})
                if submit.status_code >= 400:
                    errors += 1
                    continue
                analysis_id = ((submit.json().get("data") or {}).get("id")) or ""
                report = client.get(f"https://www.virustotal.com/api/v3/urls/{_vt_url_id(part.original)}")
                if report.status_code >= 400:
                    errors += 1
                    continue
                stats = (
                    ((report.json().get("data") or {}).get("attributes") or {}).get("last_analysis_stats")
                    or {}
                )
                malicious = int(stats.get("malicious") or 0)
                suspicious = int(stats.get("suspicious") or 0)
                details[part.registrable_domain or part.host] = malicious
                if malicious or suspicious:
                    flagged += 1
                    findings.append(
                        Finding(
                            id=f"rep-vt-{part.registrable_domain}",
                            title="VirusTotal vendors flagged a link",
                            severity="high",
                            score_points=28,
                            explanation=(
                                f"VirusTotal reports malicious={malicious}, suspicious={suspicious} for "
                                f"{part.registrable_domain or part.host}. Several security vendors already "
                                "distrust this address."
                            ),
                            lever="none",
                            category="reputation",
                            evidence=str(stats),
                        )
                    )
                _ = analysis_id
        if errors and not details:
            return ExternalCheck(
                name="VirusTotal",
                status="could_not_run",
                source=source,
                checked_at=_now(),
                summary=f"Could not run — {errors} request(s) failed.",
            )
        summary = (
            f"Looked up {len(details)} URL(s); {flagged} flagged."
            if details
            else "Looked up URLs; none flagged (not a guarantee of safety)."
        )
        return ExternalCheck(
            name="VirusTotal",
            status="ok",
            source=source,
            checked_at=_now(),
            summary=summary,
            details=details,
        )
    except Exception as exc:
        return ExternalCheck(
            name="VirusTotal",
            status="could_not_run",
            source=source,
            checked_at=_now(),
            summary=f"Could not run — {type(exc).__name__}.",
        )


def _vt_url_id(url: str) -> str:
    import base64

    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _rdap_ages(urls: list[UrlPart], findings: list[Finding]) -> list[ExternalCheck]:
    source = "RDAP (rdap.org/domain/{domain})"
    domains: list[str] = []
    seen: set[str] = set()
    for part in urls:
        if part.is_ip:
            continue
        d = part.registrable_domain
        if not d or d in seen or "." not in d:
            continue
        seen.add(d)
        domains.append(d)
        if len(domains) >= 3:
            break
    if not domains:
        return [
            ExternalCheck(
                name="RDAP domain age",
                status="skipped",
                source=source,
                checked_at=_now(),
                summary="No domain names to look up.",
            )
        ]
    checks: list[ExternalCheck] = []
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
            for domain in domains:
                try:
                    response = client.get(f"https://rdap.org/domain/{quote(domain)}")
                    if response.status_code == 404:
                        checks.append(
                            ExternalCheck(
                                name=f"RDAP ({domain})",
                                status="could_not_run",
                                source=source,
                                checked_at=_now(),
                                summary="Could not run — domain not found in RDAP.",
                            )
                        )
                        continue
                    if response.status_code >= 400:
                        checks.append(
                            ExternalCheck(
                                name=f"RDAP ({domain})",
                                status="could_not_run",
                                source=source,
                                checked_at=_now(),
                                summary=f"Could not run — HTTP {response.status_code}.",
                            )
                        )
                        continue
                    created = _created_date(response.json())
                    if not created:
                        checks.append(
                            ExternalCheck(
                                name=f"RDAP ({domain})",
                                status="ok",
                                source=source,
                                checked_at=_now(),
                                summary="Connected, but no registration start date was published.",
                                details={"domain": domain},
                            )
                        )
                        continue
                    age_days = (datetime.now(timezone.utc) - created).days
                    if age_days < 30:
                        findings.append(
                            Finding(
                                id=f"rep-rdap-new-{domain}",
                                title=f"Domain {domain} is very new",
                                severity="high",
                                score_points=20,
                                explanation=(
                                    f"RDAP shows this domain was registered about {age_days} day(s) ago. "
                                    "Phishing sites are often stood up and thrown away within weeks."
                                ),
                                lever="none",
                                category="reputation",
                                evidence=created.date().isoformat(),
                            )
                        )
                    elif age_days < 180:
                        findings.append(
                            Finding(
                                id=f"rep-rdap-young-{domain}",
                                title=f"Domain {domain} is less than 6 months old",
                                severity="medium",
                                score_points=10,
                                explanation=(
                                    f"RDAP registration age is about {age_days} days. Genuine Indian banks "
                                    "and government domains are years old."
                                ),
                                lever="none",
                                category="reputation",
                                evidence=created.date().isoformat(),
                            )
                        )
                    checks.append(
                        ExternalCheck(
                            name=f"RDAP ({domain})",
                            status="ok",
                            source=source,
                            checked_at=_now(),
                            summary=f"Registered about {age_days} day(s) ago ({created.date().isoformat()}).",
                            details={"domain": domain, "age_days": age_days},
                        )
                    )
                except Exception as exc:
                    checks.append(
                        ExternalCheck(
                            name=f"RDAP ({domain})",
                            status="could_not_run",
                            source=source,
                            checked_at=_now(),
                            summary=f"Could not run — {type(exc).__name__}.",
                        )
                    )
    except Exception as exc:
        checks.append(
            ExternalCheck(
                name="RDAP domain age",
                status="could_not_run",
                source=source,
                checked_at=_now(),
                summary=f"Could not run — {type(exc).__name__}.",
            )
        )
    return checks


def _created_date(data: dict) -> datetime | None:
    events = data.get("events") or []
    for event in events:
        action = str(event.get("eventAction") or "").lower()
        if action in {"registration", "registered"}:
            raw = event.get("eventDate")
            if raw:
                return _parse_dt(str(raw))
    return None


def _parse_dt(raw: str) -> datetime | None:
    raw = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None
