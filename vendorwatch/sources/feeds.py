"""Unstructured sources: Google News, Exploit-DB, vendor PSIRT feeds, security news RSS."""
from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote_plus

from . import Http, log
from .vulns import CVE_RE

GOOGLE_NEWS = "https://news.google.com/rss/search?q={q}&hl=en-US&gl=US&ceid=US:en"
EXPLOITDB_RSS = "https://www.exploit-db.com/rss.xml"

RISK_TERMS = (
    "vulnerability", "vulnerabilities", "exploit", "exploited", "zero-day", "0-day", "CVE",
    "patch", "breach", "ransomware", "hacked", "cyberattack", "data leak", "compromised", "outage",
)

# keyword -> category, checked in order (first hit wins)
CATEGORIES = [
    ("exploit", ("actively exploited", "exploited in the wild", "zero-day", "0-day", "proof-of-concept",
                 "proof of concept", "poc", "exploit", "under attack", "mass exploitation", "kev")),
    ("breach", ("breach", "ransomware", "hacked", "data leak", "leaked", "stolen", "extortion", "compromised",
                "cyberattack", "cyber attack", "intrusion", "attackers accessed")),
    ("patch", ("patch", "fixes", "fixed", "update", "advisory", "security bulletin", "hotfix", "firmware")),
    ("vulnerability", ("vulnerability", "vulnerabilities", "flaw", "cve-", "bug", "rce", "remote code")),
    ("outage", ("outage", "down", "disruption")),
]


def _text(el, *names) -> str:
    for n in names:
        found = el.find(n)
        if found is not None:
            if found.text:
                return found.text.strip()
            if found.get("href"):
                return found.get("href")
    return ""


def _parse_date(s: str) -> str:
    if not s:
        return ""
    try:
        return parsedate_to_datetime(s).astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except ValueError:
        return s


def _strip_html(s: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html.unescape(s or ""))).strip()


def parse_feed(xml_text: str) -> list[dict]:
    """Minimal RSS 2.0 / Atom parser (stdlib only)."""
    xml_text = re.sub(r'\sxmlns="[^"]+"', "", xml_text, count=1)  # drop default Atom ns
    root = ET.fromstring(xml_text.encode("utf-8") if isinstance(xml_text, str) else xml_text)
    items = root.findall(".//item") or root.findall(".//entry")
    out = []
    for it in items:
        title = _strip_html(_text(it, "title"))
        link = _text(it, "link")
        if not link:
            le = it.find("link")
            link = le.get("href", "") if le is not None else ""
        source_el = it.find("source")
        out.append(
            {
                "title": title,
                "url": link,
                "published": _parse_date(_text(it, "pubDate", "published", "updated", "{http://purl.org/dc/elements/1.1/}date")),
                "summary": _strip_html(_text(it, "description", "summary", "content"))[:600],
                "source": (source_el.text or "").strip() if source_el is not None and source_el.text else "",
            }
        )
    return out


def categorize(text: str) -> str:
    t = (text or "").lower()
    for cat, words in CATEGORIES:
        if any(w in t for w in words):
            return cat
    return "general"


def extract_cves(text: str) -> list[str]:
    return sorted({c.upper() for c in CVE_RE.findall(text or "")})


def matches_terms(text: str, terms: list[str]) -> bool:
    t = (text or "").lower()
    for term in terms:
        term = term.lower().strip()
        if not term:
            continue
        # word-boundary match so "Ivanti" doesn't match "Ivantis", but allow "FortiOS" inside "FortiOS-7.4"
        if re.search(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", t):
            return True
    return False


def google_news(http: Http, terms: list[str], days: int) -> list[dict]:
    """Google News RSS search for risk-relevant coverage of the asset."""
    who = " OR ".join(f'"{t}"' for t in terms[:6])
    what = " OR ".join(f'"{w}"' if " " in w else w for w in RISK_TERMS)
    q = f"({who}) ({what}) when:{max(1, days)}d"
    try:
        r = http.get(GOOGLE_NEWS.format(q=quote_plus(q)), retries=2, backoff=3)
        items = parse_feed(r.text)
    except Exception as e:  # noqa: BLE001
        log.warning("Google News failed for %s: %s", terms, e)
        return []
    for i in items:
        # Google appends " - Publisher" to titles
        if not i["source"] and " - " in i["title"]:
            i["source"] = i["title"].rsplit(" - ", 1)[1]
    return items


def fetch_feed(http: Http, url: str) -> list[dict]:
    try:
        return parse_feed(http.get(url, retries=2, backoff=3).text)
    except Exception as e:  # noqa: BLE001
        log.warning("feed %s failed: %s", url, e)
        return []


def exploitdb(http: Http) -> list[dict]:
    return fetch_feed(http, EXPLOITDB_RSS)
