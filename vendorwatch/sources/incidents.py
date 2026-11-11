"""Incident sources: ransomware leak sites (via ransomware.live) and SEC 8-K cyber disclosures."""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from urllib.parse import quote

from . import Http, log

RANSOMWARE_RECENT = "https://api.ransomware.live/v2/recentvictims"
RANSOMWARE_MONTH = "https://api.ransomware.live/v2/victims/{year}/{month:02d}"

EFTS = "https://efts.sec.gov/LATEST/search-index"  # company search (ticker -> CIK)
EDGAR_DOC = "https://www.sec.gov/Archives/edgar/data/{cik}/{adsh}/{doc}"

_CORP = re.compile(r"\b(inc|incorporated|llc|ltd|limited|corp|corporation|co|company|plc|gmbh|sa|ag|group|holdings)\b\.?", re.I)


def _norm_name(s: str) -> str:
    s = _CORP.sub(" ", (s or "").lower())
    return re.sub(r"[^a-z0-9]", "", s)


def _norm_domain(d: str) -> str:
    d = (d or "").lower().strip()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0]
    return d[4:] if d.startswith("www.") else d


# --------------------------------------------------------------------- ransomware.live
def victim_matches(v: dict, asset) -> bool:
    """Match a leak-site victim to an asset by domain, or by company name (never by description)."""
    vd = _norm_domain(v.get("domain") or "")
    for d in asset.domains:
        d = _norm_domain(d)
        if vd and (vd == d or vd.endswith("." + d)):
            return True
    name = v.get("victim") or ""
    if not name:
        return False
    nn = _norm_name(name)
    # victims are sometimes listed by their domain: "hawksoft.com"
    if "." in name and " " not in name.strip():
        nd = _norm_domain(name)
        if any(nd == _norm_domain(d) or nd.endswith("." + _norm_domain(d)) for d in asset.domains):
            return True
    terms = [asset.name] + list(asset.keywords)
    if asset.domains:
        # with domains configured, require the (normalised) name to be exactly the vendor's
        # name, so "Adobe Dental Clinic" doesn't match Adobe
        return any(nn and nn == _norm_name(t) for t in terms)
    return any(nn and _norm_name(t) and (nn == _norm_name(t) or nn.startswith(_norm_name(t)) and len(_norm_name(t)) >= 5)
               for t in terms)


def ransomware_recent(http: Http) -> list[dict]:
    try:
        return http.get(RANSOMWARE_RECENT, retries=2, backoff=5).json() or []
    except Exception as e:  # noqa: BLE001
        log.warning("ransomware.live recent victims failed: %s", e)
        return []


def months_back(now: datetime, days: int) -> list[tuple[int, int]]:
    """(year, month) pairs covering the last `days` days, newest first."""
    out, y, m = [], now.year, now.month
    start = now.timestamp() - days * 86400
    while True:
        out.append((y, m))
        if datetime(y, m, 1, tzinfo=timezone.utc).timestamp() <= start:
            return out
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)


def ransomware_months(http: Http, months: list[tuple[int, int]]) -> tuple[list[dict], bool]:
    """All leak-site victims posted in the given months (~1,000/month, one request each).

    Bulk monthly downloads instead of per-vendor searches: the free API rate-limits
    searches hard, and one download serves every vendor on the watchlist.
    Returns (victims, complete) - complete is False if any month failed.
    """
    victims, ok = [], True
    for i, (y, m) in enumerate(months):
        if i:
            time.sleep(3)  # free community API - stay well under its rate limit
        try:
            victims += http.get(RANSOMWARE_MONTH.format(year=y, month=m), retries=3, backoff=20).json() or []
        except Exception as e:  # noqa: BLE001
            log.warning("ransomware.live %d-%02d failed: %s", y, m, e)
            ok = False
    return victims, ok


def victim_record(v: dict) -> dict:
    vid = v.get("id") or v.get("url") or f"{v.get('group')}:{v.get('victim')}"
    page = v.get("url") if str(v.get("url", "")).startswith("https://www.ransomware.live") else ""
    if not page:
        page = "https://www.ransomware.live/search/" + quote(v.get("victim") or "")
    return {
        "id": str(vid),
        "victim": v.get("victim", ""),
        "domain": v.get("domain", ""),
        "group": v.get("group", ""),
        "attackdate": v.get("attackdate", ""),
        "discovered": v.get("discovered", ""),
        "country": v.get("country", ""),
        "activity": v.get("activity", ""),
        "description": (v.get("description") or "")[:500],
        "url": page,
    }


# --------------------------------------------------------------------- SEC EDGAR
SUBMISSIONS = "https://data.sec.gov/submissions/CIK{cik}.json"
CYBER_RE = re.compile(
    r"cybersecurity incident|cyber[- ]?attack|unauthori[sz]ed access|ransomware|threat actor|"
    r"unauthori[sz]ed third[- ]party|data security incident|security incident|malicious activity|"
    r"exfiltrat", re.I)


class Sec:
    """SEC EDGAR. Uses the official per-company filing index (data.sec.gov/submissions),
    which lists every 8-K with its item numbers - Item 1.05 is the mandatory
    "material cybersecurity incident" disclosure. SEC asks automated clients to identify
    themselves in the User-Agent ("Company contact@example.com") and to stay under
    10 requests/second."""

    def __init__(self, http: Http, user_agent: str = ""):
        self.http = http
        self.headers = {"User-Agent": user_agent} if user_agent else None

    def _get(self, url: str, params: dict | None = None):
        time.sleep(0.2)
        return self.http.get(url, params=params, headers=self.headers, retries=3, backoff=5)

    def resolve_cik(self, ticker: str, name: str = "") -> str | None:
        """Best-effort ticker -> CIK via EDGAR company search. Setting `sec_cik` is more reliable."""
        for q in filter(None, (ticker, name)):
            d = self._get(EFTS, {"keysTyped": q}).json()
            for h in d.get("hits", {}).get("hits", []):
                tickers = str(h.get("_source", {}).get("tickers", "")).upper().replace(" ", "").split(",")
                if ticker.upper() in tickers:
                    return str(h["_id"]).zfill(10)
        return None

    def filings_8k(self, cik: str, start: datetime) -> list[dict]:
        d = self._get(SUBMISSIONS.format(cik=cik.zfill(10))).json()
        r = d.get("filings", {}).get("recent", {})
        out = []
        for i, form in enumerate(r.get("form", [])):
            if form not in ("8-K", "8-K/A"):
                continue
            filed = r["filingDate"][i]
            if filed < start.strftime("%Y-%m-%d"):
                continue
            adsh = r["accessionNumber"][i]
            out.append({
                "adsh": adsh,
                "form": form,
                "file_date": filed,
                "items": [x.strip() for x in str(r.get("items", [""] * (i + 1))[i]).split(",") if x.strip()],
                "company": d.get("name", ""),
                "url": EDGAR_DOC.format(cik=int(cik), adsh=adsh.replace("-", ""), doc=r["primaryDocument"][i]),
            })
        return out

    def mentions_cyber(self, url: str) -> bool:
        try:
            text = re.sub(r"<[^>]+>", " ", self._get(url).text)
        except Exception as e:  # noqa: BLE001
            log.debug("could not read %s: %s", url, e)
            return False
        return bool(CYBER_RE.search(text))


def classify_8k(items: list[str]) -> str | None:
    """'material' for Item 1.05, 'voluntary' for an Item 8.01 cyber disclosure, None to ignore.

    Earnings releases (2.02) and investor decks (7.01 alone) routinely contain cyber
    risk boilerplate, so a keyword hit in those is not treated as a disclosure.
    """
    items = [str(i) for i in items]
    if "1.05" in items:
        return "material"
    if "8.01" in items and "2.02" not in items:
        return "voluntary"
    return None
